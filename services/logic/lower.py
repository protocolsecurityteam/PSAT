"""Slither IR to one formula: the condition under which a call returns instead of reverting.

Forward symbolic execution over each function's control-flow graph, in topological order with merges at joins, so the
work is linear in the graph however many branches it has. The rules are the language's, not any contract's:

* ``require``/``assert`` conjoin their condition to the path; ``revert`` and ``throw`` end it.
* ``if`` splits the path; where branches meet, the path conditions are or-ed and the values they disagree on become
  ``ite``.
* Internal and library calls run inline with their parameters bound; a modifier runs the rest of the function at its
  ``_``.
* A loop exits either before its first iteration, or after one iteration followed by an unknown number of further
  ones: everything the body changed is forgotten and the path carries an ``unknown`` conjunct, so it can widen what
  may pass but never proves anything passes.
* Storage reads see earlier writes in the same call; external calls are values (``call`` terms) whose answer the
  decision step reads from the chain.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any

from eth_utils.crypto import keccak
from slither.core.cfg.node import NodeType
from slither.core.declarations import (
    Contract,
    Function,
    Modifier,
    SolidityFunction,
    SolidityVariable,
    SolidityVariableComposed,
)
from slither.core.solidity_types import ElementaryType, MappingType
from slither.core.variables.state_variable import StateVariable
from slither.core.variables.top_level_variable import TopLevelVariable
from slither.slithir.operations import (
    Assignment,
    Binary,
    BinaryType,
    Condition,
    Delete,
    EventCall,
    HighLevelCall,
    Index,
    InitArray,
    InternalCall,
    InternalDynamicCall,
    Length,
    LibraryCall,
    LowLevelCall,
    Member,
    NewArray,
    NewContract,
    NewElementaryType,
    NewStructure,
    Nop,
    Return,
    Send,
    SolidityCall,
    Transfer,
    TypeConversion,
    Unary,
    UnaryType,
    Unpack,
)
from slither.slithir.operations.codesize import CodeSize
from slither.slithir.variables import Constant, ReferenceVariable

from .terms import (
    CALLDATA,
    CALLER,
    FALSE,
    IDENTITY_KINDS,
    ORIGIN,
    THIS,
    TRUE,
    Term,
    const,
    contains,
    mk,
    mk_and,
    mk_cmp,
    mk_ite,
    mk_not,
    mk_op,
    mk_or,
    mk_slice,
    packed_width,
    replace_terms,
    substitute,
    subterms,
    term_epoch,
    unknown,
)

MAX_DEPTH = 12
MAX_UNROLL = 8  # iterations whose loop condition is a known constant
MAX_SYMBOLIC_UNROLL = 2  # iterations whose condition depends on arguments or state
# Nodes one top-level call may step before loops stop unrolling and fall back to forgetting what they change.
UNROLL_BUDGET = 4_000

_BINARY = {
    BinaryType.ADDITION: "add",
    BinaryType.SUBTRACTION: "sub",
    BinaryType.MULTIPLICATION: "mul",
    BinaryType.DIVISION: "div",
    BinaryType.MODULO: "mod",
    BinaryType.POWER: "pow",
    BinaryType.LEFT_SHIFT: "shl",
    BinaryType.RIGHT_SHIFT: "shr",
    BinaryType.AND: "and",
    BinaryType.OR: "or",
    BinaryType.CARET: "xor",
}
_COMPARE = {
    BinaryType.LESS: "lt",
    BinaryType.GREATER: "gt",
    BinaryType.LESS_EQUAL: "le",
    BinaryType.GREATER_EQUAL: "ge",
    BinaryType.EQUAL: "eq",
    BinaryType.NOT_EQUAL: "ne",
}


def _calldata_min(function: Function) -> int:
    """The fewest calldata bytes a call reaching the body carries. Before 0.5 the decoder read missing bytes as zero
    (the short-address attack ``onlyPayloadSize`` guards), so only the selector; since, every argument's head, and a
    length word for each dynamic one."""
    version = str(getattr(function.compilation_unit, "solc_version", "") or "")
    parts = [int(x) for x in version.split(".")[:2] if x.isdigit()]
    if len(parts) == 2 and parts < [0, 5]:
        return 4
    total = 4
    for p in function.parameters:
        type_ = str(p.type)
        total += 64 if type_ in ("bytes", "string") or type_.endswith("[]") else 32
    return total


_ARGUMENTS_SLICE = re.compile(r"msg\.data\s*\[\s*(?:4|0x0*4)\s*:\s*\]")

_ENVIRONMENT = {
    "msg.sender": CALLER,
    "tx.origin": ORIGIN,
    "this": THIS,
    "msg.sig": mk("sig"),
    "msg.value": mk("callvalue"),
    "msg.data": CALLDATA,
    "now": mk("time", "timestamp"),
    "block.timestamp": mk("time", "timestamp"),
    "block.number": mk("time", "number"),
    "block.chainid": mk("time", "chainid"),
    "block.basefee": mk("time", "basefee"),
    "block.prevrandao": mk("time", "prevrandao"),
    "block.difficulty": mk("time", "prevrandao"),
    "block.coinbase": mk("time", "coinbase"),
    "block.gaslimit": mk("time", "gaslimit"),
}
_HASHES = ("keccak256", "sha256", "sha3")

# What the lowering does with each construct of the language Slither can hand it (``COVERAGE.md``): lowered with
# defined semantics (HANDLED), or rejected by name, its value (and, where it has effects, the path) an ``unknown`` whose
# label is the gap a verdict reports (REJECTED). Anything in neither, from a newer Slither, is rejected the same way
# (``tests/logic/test_ir_coverage.py`` fails until it is classified).
HANDLED_OPERATIONS = frozenset(
    (
        "Assignment Binary CodeSize Condition Delete EventCall HighLevelCall Index InitArray InternalCall Length "
        "LibraryCall LowLevelCall Member NewArray NewContract NewElementaryType NewStructure Nop Return SolidityCall "
        "Transfer TypeConversion Unary Unpack"
    ).split()
)
REJECTED_OPERATIONS = {
    "Phi": "unsupported:Phi",  # SSA only: never in a node's IR
    "PhiCallback": "unsupported:PhiCallback",
    "InternalDynamicCall": "unsupported:InternalDynamicCall",  # which function a pointer holds isn't followed
    "Send": "Send",  # whether the recipient accepts
}
# Names in ``slither.slithir.operations`` that are no operation of their own.
ABSTRACT_OPERATIONS = frozenset({"Call", "Operation", "OperationWithLValue", "BinaryType", "UnaryType"})

HANDLED_BUILTINS = frozenset(
    [
        "assert(bool)", "require(bool)", "require(bool,string)", "require(bool,error)", "revert()", "revert(string)",
        "revert ", "addmod(uint256,uint256,uint256)", "mulmod(uint256,uint256,uint256)", "keccak256()",
        "keccak256(bytes)", "sha256()", "sha256(bytes)", "sha3()", "ecrecover(bytes32,uint8,bytes32,bytes32)",
        "selfdestruct(address)", "suicide(address)", "log0(bytes32)", "log1(bytes32,bytes32)",
        "log2(bytes32,bytes32,bytes32)", "log3(bytes32,bytes32,bytes32,bytes32)", "prevrandao()", "this.balance()",
        "abi.encode()", "abi.encodePacked()", "abi.encodeWithSelector()", "abi.encodeWithSignature()",
        "abi.encodeCall()", "bytes.concat()", "string.concat()", "abi.decode()", "balance(address)", "code(address)",
        "codehash(address)", "byte(uint256,uint256)", "clz(uint256)", "signextend(uint256,uint256)",
        "keccak256(uint256,uint256)", "pop(uint256)", "mload(uint256)", "mstore(uint256,uint256)",
        "mstore8(uint256,uint256)", "sload(uint256)", "sstore(uint256,uint256)", "tload(uint256)",
        "tstore(uint256,uint256)", "address()", "balance(uint256)", "selfbalance()", "basefee()", "caller()",
        "callvalue()", "calldataload(uint256)", "calldatasize()", "calldatacopy(uint256,uint256,uint256)",
        "codesize()", "codecopy(uint256,uint256,uint256)", "extcodesize(uint256)",
        "extcodecopy(uint256,uint256,uint256,uint256)", "returndatasize()", "returndatacopy(uint256,uint256,uint256)",
        "mcopy(uint256,uint256,uint256)", "extcodehash(uint256)", "create(uint256,uint256,uint256)",
        "create2(uint256,uint256,uint256,uint256)", "call(uint256,uint256,uint256,uint256,uint256,uint256,uint256)",
        "callcode(uint256,uint256,uint256,uint256,uint256,uint256,uint256)",
        "delegatecall(uint256,uint256,uint256,uint256,uint256,uint256)",
        "staticcall(uint256,uint256,uint256,uint256,uint256,uint256)", "return(uint256,uint256)",
        "revert(uint256,uint256)", "selfdestruct(uint256)", "invalid()", "stop()", "log0(uint256,uint256)",
        "log1(uint256,uint256,uint256)", "log2(uint256,uint256,uint256,uint256)",
        "log3(uint256,uint256,uint256,uint256,uint256)", "log4(uint256,uint256,uint256,uint256,uint256,uint256)",
        "chainid()", "origin()", "coinbase()", "timestamp()", "number()", "difficulty()", "gaslimit()",
    ]
)  # fmt: skip
# Vyper's builtins: its semantics (bounds, checked arithmetic, calls that revert on failure) aren't this lowering's.
_VYPER = (
    "create_from_blueprint() create_minimal_proxy_to() empty() convert() len() method_id() unsafe_sub() unsafe_add() "
    "unsafe_div() unsafe_mul() pow_mod256() max_value() min_value() concat() ecrecover() isqrt() range() min() max() "
    "shift() abs() raw_call() _abi_encode() slice() uint2str() send()"
).split()
REJECTED_BUILTINS = {
    "gasleft()": "gasleft()",  # the gas the caller sends
    "gas()": "unsupported:gas()",
    "msize(uint256)": "unsupported:msize(uint256)",
    "pc()": "unsupported:pc()",
    "blockhash(uint256)": "unsupported:blockhash(uint256)",
    "blobhash(uint256)": "unsupported:blobhash(uint256)",
    "blobbasefee()": "unsupported:blobbasefee()",
    "gasprice()": "unsupported:gasprice()",  # any price the caller pays at or above the base fee
    "type(address)": "unsupported:type(address)",
    "type()": "unsupported:type()",
    "ripemd160()": "unsupported:ripemd160()",  # no implementation to evaluate it with
    "ripemd160(bytes)": "unsupported:ripemd160(bytes)",
    **{name: f"unsupported:vyper:{name}" for name in _VYPER},
}
_YUL_ENVIRONMENT = {
    "timestamp": mk("time", "timestamp"),
    "number": mk("time", "number"),
    "chainid": mk("time", "chainid"),
    "basefee": mk("time", "basefee"),
    "coinbase": mk("time", "coinbase"),
    "gaslimit": mk("time", "gaslimit"),
    "difficulty": mk("time", "prevrandao"),
    "prevrandao": mk("time", "prevrandao"),
    "origin": ORIGIN,
    "callvalue": mk("callvalue"),
}

# The legacy Yul reader (``_yul``, for assembly Slither leaves as text before Solidity 0.6), by builtin: read with the
# meaning the same operation has in Solidity, read as an unknown by name, or refused (``yul.Unsupported``: the text
# falls back to ``_legacy_assembly``, which forgets what the block assigns and marks what it may write or call).
LEGACY_YUL_HANDLED = frozenset(
    (
        "add sub mul div mod exp and or xor shl shr lt gt eq slt sgt iszero not sload caller address callvalue "
        "timestamp number extcodesize calldataload sdiv smod sar byte signextend calldatasize chainid selfbalance "
        "balance addmod mulmod sstore mstore mstore8 calldatacopy codecopy returndatacopy pop log1 log2 log3 log4 "
        "revert invalid"
    ).split()
)
LEGACY_YUL_OPAQUE = {
    "mload": "mload(uint256)",  # memory this reading doesn't track: a lost word
    "keccak256": "keccak256",
    "gas": "gas",
    "returndatasize": "returndatasize",
    "msize": "msize",
}
LEGACY_YUL_UNSUPPORTED = frozenset(
    (
        "basefee blobbasefee blobhash blockhash call callcode clz codesize coinbase create create2 datacopy "
        "dataoffset datasize delegatecall difficulty extcodecopy extcodehash gaslimit gasprice loadimmutable log0 "
        "mcopy origin pc prevrandao return selfdestruct setimmutable staticcall stop tload tstore"
    ).split()
)
LEGACY_YUL_STATEMENTS = frozenset(
    "sstore mstore mstore8 calldatacopy codecopy returndatacopy pop log1 log2 log3 log4 revert invalid".split()
)
LEGACY_YUL_ARITY = {
    **dict.fromkeys("iszero not sload extcodesize calldataload balance mload pop".split(), 1),
    **dict.fromkeys(
        "caller address callvalue timestamp number calldatasize chainid selfbalance gas returndatasize msize "
        "invalid".split(),
        0,
    ),
    **dict.fromkeys("addmod mulmod calldatacopy codecopy returndatacopy log1".split(), 3),
    "log2": 4,
    "log3": 5,
    "log4": 6,
}

HANDLED_VARIABLES = frozenset(
    (
        "now this msg.sender tx.origin msg.value msg.sig msg.data block.timestamp block.number block.chainid "
        "block.basefee block.prevrandao block.difficulty block.coinbase block.gaslimit"
    ).split()
)
REJECTED_VARIABLES = {
    "tx.gasprice": "unsupported:tx.gasprice",  # any price the caller pays at or above the base fee
    "block.blobbasefee": "unsupported:block.blobbasefee",
    "block.blockhash": "unsupported:block.blockhash",
    "msg.gas": "unsupported:msg.gas",
    # Vyper's, and namespaces that are never a value.
    **{
        name: f"unsupported:{name}"
        for name in ("self", "chain", "ZERO_ADDRESS", "chain.id", "block.prevhash", "self.balance")
        + ("abi", "msg", "tx", "block", "super")
    },
}

# Assembly builtins that leave memory as it was (``mstore`` and the calls track what they write themselves).
_MEMORY_NEUTRAL = frozenset(
    (
        "mstore mload sload keccak256 require assert calldataload calldatasize extcodesize extcodehash staticcall "
        "call callcode returndatasize returndatacopy "
        "balance selfbalance gas chainid timestamp number caller address origin callvalue byte signextend"
    ).split()
)
_MEMORY_SPAN = 0x400  # how far above zero constant-offset assembly memory is followed
# Where assembly that reads the free memory pointer (``mload(0x40)``) before writing it finds free memory: a window of
# its own, followed like the one above zero (GPv2's ``safeTransferFrom`` building its call there).
_FREE_MEMORY = 2**32


def parameter(param: Any, index: int) -> Term:
    """A caller-chosen argument, typed as the ABI sees it: an enum is a ``uint8`` (and a contract an address)."""
    return _typed_arg(param.name or f"arg{index}", param.type)


def _typed_arg(name: str, type_: Any) -> Term:
    from slither.core.declarations import Contract, Enum
    from slither.core.solidity_types import UserDefinedType

    abi = str(type_)
    if isinstance(type_, UserDefinedType) and isinstance(type_.type, Enum):
        abi = "uint8"
    elif isinstance(type_, UserDefinedType) and isinstance(type_.type, Contract):
        abi = "address"
    return mk("arg", name, abi)


def _enum_of(var: Any) -> Any:
    """The enum ``var`` names, when it is an enum type itself (the left of ``Operation.Call``)."""
    from slither.core.declarations import Enum
    from slither.core.solidity_types import UserDefinedType

    if isinstance(var, UserDefinedType):
        var = var.type
    return var if isinstance(var, Enum) else None


def _ran_under(operand: Term, guard: Term) -> Term:
    """A short-circuited operand as the operator sees it: merged, it reads ``ite(... and guard, value, unset)``, and
    where the guard fails the operator never looks at it (``a && b`` is ``a and b``)."""
    if operand[0] != "ite" or operand[3][0] != "unknown" or operand[3][1] != "unset":
        return operand
    condition = operand[1]
    parts = condition[1] if condition[0] == "and" else frozenset({condition})
    needed = guard[1] if guard[0] == "and" else frozenset({guard})  # ``a && b && c``: c ran under a and b
    return operand[2] if needed <= parts else operand


def _keeps_memory(ir: Any) -> bool:
    """Whether ``ir`` can't write memory: plain arithmetic, copies, conditions, memory-neutral builtins (Yul's form,
    ``name(uint256,...)``; Solidity's ``keccak256(bytes)`` encodes into memory first)."""
    if isinstance(ir, (Assignment, Binary, Unary, TypeConversion, Condition)):
        return True
    if isinstance(ir, SolidityCall):
        name = ir.function.name
        return name.split("(", 1)[0] in _MEMORY_NEUTRAL and "bytes" not in name
    return False


def _small_const(term: Any) -> int | None:
    if isinstance(term, tuple) and term[0] == "const" and isinstance(term[1], int) and not isinstance(term[1], bool):
        value = term[1]
        return value if 0 <= value < _MEMORY_SPAN or _FREE_MEMORY <= value < _FREE_MEMORY + _MEMORY_SPAN else None
    return None


def _memory_bytes(mem: tuple, start: int | None, length: int | None) -> tuple | None:
    """Memory [start, start+length) as the words that last wrote each byte, cut to the bytes each still holds;
    ``None`` when any byte there was never written by this assembly."""
    if start is None or length is None or not 0 < length <= _MEMORY_SPAN:
        return None
    if start % _FREE_MEMORY + length > _MEMORY_SPAN:
        return None
    owner: list[int | None] = [None] * length
    for i, (offset, _) in enumerate(mem):
        for b in range(max(offset, start), min(offset + 32, start + length)):
            owner[b - start] = i
    if any(o is None for o in owner):
        return None
    pieces = []
    b = 0
    while b < length:
        i = owner[b]
        e = b
        while e < length and owner[e] == i:
            e += 1
        offset, word = mem[i]  # type: ignore[index]
        pieces.append(mk_slice(word, start + b - offset, e - b))
        b = e
    return tuple(pieces)


def _one_word(type_: str) -> bool:
    """A static type ABI-encoded in exactly one word."""
    if "[" in type_ or type_.startswith("(") or type_ in ("bytes", "string"):
        return False
    return type_ in ("address", "bool") or type_.startswith(("uint", "int", "bytes"))


_FRAME_KINDS = frozenset({"sig", "callvalue", "calldatasize"})


def _frame_bound(term: Term) -> bool:
    """Whether ``term`` reads the call frame it was written in (its ``msg.data``, ``msg.sig``, ``msg.value``)."""
    return contains(term, _FRAME_KINDS) or CALLDATA in subterms(term, "arg")


def _selector_word(t: Term) -> bool:
    """``shl(224, shr(224, calldataload(0)))``: the call's selector, left-aligned in a word (Slither puts the
    shifted value first, ``x >> 224``)."""

    def shifted(term: Any, name: str) -> Any:
        if not (isinstance(term, tuple) and term[:2] == ("op", name) and len(term[2]) == 2):
            return None
        a, b = term[2]
        return a if _small_const(b) == 224 else b if _small_const(a) == 224 else None

    inner = shifted(t, "shl")
    return inner is not None and shifted(inner, "shr") == mk("elem", CALLDATA, const(0))


def _call_arguments(text: str, start: int) -> list[str] | None:
    """The comma-separated arguments of the call whose ``(`` ends just before ``start``, split at its own depth."""
    depth, parts, current = 1, [], []
    for i in range(start, len(text)):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                parts.append("".join(current).strip())
                return parts
        elif ch == "," and depth == 1:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    return None


def _packed_item(pointer: Term, width: int) -> Term | None:
    """The item of ``width`` bytes starting at ``pointer`` (``add(data, k)``) in bytes an ``abi.encodePacked`` built,
    ``data`` being where their length is kept: what ``mload`` reads there (a signature's ``r`` and ``s``)."""
    if not (isinstance(pointer, tuple) and pointer[:2] == ("op", "add") and len(pointer[2]) == 2):
        return None
    data, offset = pointer[2]
    if _small_const(data) is not None:
        data, offset = offset, data
    at = _small_const(offset)
    if at is None or not (isinstance(data, tuple) and data[:2] == ("enc", "abi.encodePacked")):
        return None
    position = 32  # past the length word
    for item in data[2]:
        size = packed_width(item)
        if size is None:
            return None
        if position == at:
            return item if size == width else None
        position += size
    return None


def _memory_word(mem: tuple, offset: int | None) -> Any:
    """``mload(offset)``: the word stored there, when one ``mstore`` wrote all 32 bytes and nothing since."""
    pieces = _memory_bytes(mem, offset, 32)
    if pieces is None or len(pieces) != 1:
        return None
    piece = pieces[0]
    return piece[1] if piece[0] == "slice" else piece  # all 32 bytes of one word: the word itself


@dataclass
class State:
    pc: Term
    env: dict = field(default_factory=dict)  # this frame's locals, by id(variable)
    store: dict = field(default_factory=dict)  # storage written so far in the call: (contract, var, path) -> value
    ret: tuple | None = None  # the function's return values once known (a modifier carries them past ``_``)
    halted: bool = False  # an assembly ``return``/``stop`` ended the call successfully
    # Words assembly ``mstore``d at constant offsets, in order: (offset, value). Emptied by anything else that may
    # write memory, so a ``keccak256(p, n)`` over it only ever sees bytes this assembly put there.
    mem: tuple = ()


@dataclass
class Exit:
    pc: Term
    store: dict
    ret: tuple | None
    halted: bool = False  # an assembly ``return``/``stop``: the whole call ends here, whichever function ran it


def merge(states: list[State]) -> State:
    if len(states) == 1:
        return states[0]
    pc = mk_or([s.pc for s in states])
    return State(
        pc,
        _merge_maps(states, "env"),
        _merge_store(states),
        _merge_ret(states),
        mem=states[0].mem if all(s.mem == states[0].mem for s in states) else (),
    )


def _merge_maps(states: list[Any], attr: str) -> dict:
    keys: dict = {}
    for s in states:
        keys.update(dict.fromkeys(getattr(s, attr)))
    out = {}
    for key in keys:
        # A local a branch never set is unset.
        values = [getattr(s, attr).get(key, unknown("unset")) for s in states]
        if any(isinstance(v, tuple) and v[:1] == ("loc",) for v in values) and len(set(values)) > 1:
            # A storage pointer that points at one place or another by branch: not one location (``_write``).
            out[key] = unknown("unsupported:storage_pointer_choice")
            continue
        out[key] = _select([s.pc for s in states], values)
    return out


def _merge_store(states: list[Any]) -> dict:
    """The writes of several paths as one store. A store is read in write order (``read_store``: the last write whose
    location may be the one read wins), so each merged entry is, on every path, the value its location holds at the end
    of that path: the path's own entry when nothing it wrote later may land there, else what the path reads back there
    (a location one branch left alone reads back as that branch left it, earlier writes at keys that may equal it
    included). Two writes two paths made in opposite orders are both read back that way, so no order is taken from
    either path."""
    keys: dict = {}
    for s in states:
        keys.update(dict.fromkeys(s.store))
    positions = [{k: i for i, k in enumerate(s.store)} for s in states]
    reread: set = set()
    by_place: dict = {}
    for key in keys:
        if key[0] not in ("act", "emit", "havoc", "heap"):
            by_place.setdefault((key[0], key[1]), []).append(key)
    for group in by_place.values():
        if len(group) < 2:
            continue
        for i, a in enumerate(group):
            for b in group[i + 1 :]:
                if not _may_alias(a, b):
                    continue
                orders = {pos[a] < pos[b] for pos in positions if a in pos and b in pos}
                if len(orders) > 1:
                    reread.update((a, b))
    out = {}
    for key in keys:
        values = [s.store[key] if key in s.store and key not in reread else read_store(s.store, key) for s in states]
        out[key] = _select([s.pc for s in states], values)
    return out


def stored(store: dict, key: tuple, value: Term) -> dict:
    """``store`` with ``key`` written last: a store is read in write order, so a location written again moves to the
    end (a later write at a key that may equal it no longer hides it)."""
    out = {k: v for k, v in store.items() if k != key}
    out[key] = value
    return out


def _may_alias(a: tuple, b: tuple) -> bool:
    """Whether two store keys of one place may name overlapping storage: a path and one inside it, or keys that
    aren't two different fixed values."""
    if a[0] in ("raw", "transient"):
        return not (_fixed(a[2]) and _fixed(b[2]) and a[2] != b[2])
    for (ka, x), (kb, y) in zip(a[2], b[2]):
        if ka != kb or (ka == "f" and x != y):
            return False
        if ka == "k" and _fixed(x) and _fixed(y) and x != y:
            return False
    return True


def _fixed(t: Any) -> bool:
    return isinstance(t, tuple) and bool(t) and t[0] == "const"


def read_store(store: dict, key: tuple) -> Term:
    """What ``key`` (a store key: a location, a raw or transient slot, or a mark) reads in a call whose writes so far
    are ``store``: each write whose location may be this one, in order, over the value before the call. A write of the
    whole of what is read inside of (``cfg = Cfg(..)`` then ``cfg.live``) gives the part of it read; a write inside of
    what is read whole (``list.push(x)`` then ``list`` copied to memory) gives the whole with that part replaced
    (``upd``). A loop that may have written the variable further (``havoc``) leaves it unknown from there."""
    kind = key[0]
    if kind == "heap":
        return store.get(key, unknown("unallocated"))  # an object one path never allocated: never reached there
    if kind in ("act", "emit", "havoc"):
        value = FALSE
        for k, written in store.items():
            if k == key:
                value = written
        return value
    if kind in ("raw", "transient"):
        return _read_slot(store, key)
    contract, name, path = key
    value: Term = mk("load", contract, name, path)
    for k, written in store.items():
        head = k[0]
        if head == "havoc":
            if k[1] == contract and k[2] in (name, "*", "*elsewhere"):
                value = mk_ite(written, _forgotten(k, mk("load", contract, name, path)), value)
            continue
        if head == "raw" and k[1] == contract:
            if _may_hold_named(k[2]):
                value = _raw_named(mk("load", contract, name, path))  # an assembly write that may land in it
            continue
        if head in ("act", "emit", "transient", "raw", "heap") or head != contract or k[1] != name:
            continue
        kpath = k[2]
        n = min(len(kpath), len(path))
        same = []
        for (ka, a), (kb, b) in zip(kpath[:n], path[:n]):
            if ka != kb:
                same = [FALSE]
                break
            same.append(mk_cmp("eq", a, b) if ka == "k" else (TRUE if a == b else FALSE))
        cond = mk_and(same)
        if cond == FALSE:
            continue
        if len(kpath) == len(path):
            part = written
        elif len(kpath) < len(path):
            part = project(written, path[len(kpath) :])
        else:
            part = mk("upd", value, kpath[len(path) :], written)
        value = mk_ite(cond, part, value)
    return value


def _read_slot(store: dict, key: tuple) -> Term:
    """A raw (``sload``) or transient (``tload``) slot as this call's writes leave it."""
    kind, contract, slot = key
    value: Term = mk("rawload", contract, slot) if kind == "raw" else mk("const", 0, "uint256")
    for k, written in store.items():
        if k[0] == "havoc" and k[1] == contract and k[2] in (kind, "*", "*elsewhere"):
            value = mk_ite(written, _forgotten(k, mk("rawload", contract, slot)), value)
        elif k[0] == kind and k[1] == contract:
            value = mk_ite(mk_cmp("eq", k[2], slot), written, value)
        elif kind == "raw" and k[0] == contract and _may_hold_named(slot):
            # A named variable written, then a slot read that may be its own: which bytes it changed isn't placed.
            value = _raw_named(mk("rawload", contract, slot))
    return value


def _may_hold_named(slot: Term) -> bool:
    """Whether a raw slot may be one a named variable occupies: anything but a hash, or a constant derived from one
    (namespaced storage, ERC-1967 slots), which no declared variable's slot collides with."""
    if slot[0] == "const":
        return isinstance(slot[1], int) and not isinstance(slot[1], bool) and slot[1] < 2**64
    return not _hash_based(slot)


def _hash_based(slot: Term) -> bool:
    if slot[0] == "hash":
        return True
    return slot[0] == "op" and slot[1] in ("add", "sub", "xor") and any(_hash_based(a) for a in slot[2])


def _raw_named(load: Term) -> Term:
    return mk("opaque", "unsupported:raw_named_alias", (load,))


def _forgotten(mark: tuple, load: Term) -> Term:
    """A location a loop may have written in iterations not followed: unknown, one value per location, depending on
    whoever the loop's iterations did."""
    tag = mark[3]
    steered = not tag.endswith((":anyone", ":nobody"))
    return mk("opaque", tag, (load, unknown(tag)) if steered else (load,))


_SHARED: dict = {}
# Steps the value operations below (``element``, ``update``, ...) may take for one lowering: past it each answers
# unknown by name (``budget:value_steps``) instead of unfolding further.
VALUE_STEPS = 50_000
_STEPS = [VALUE_STEPS]


def _spent() -> bool:
    _STEPS[0] -= 1
    return _STEPS[0] < 0


def _shared(fn: Callable) -> Callable:
    """``fn`` remembered per argument tuple (within one intern table): values are DAGs whose shared parts a plain
    recursion would visit once per path."""

    def call(*args: Any) -> Any:
        key = (fn.__name__, term_epoch(), *args)
        try:
            return _SHARED[key]
        except KeyError:
            pass
        except TypeError:
            return fn(*args)  # an unhashable argument: computed every time
        if len(_SHARED) > 200_000:
            _SHARED.clear()
        value = fn(*args)
        if _STEPS[0] >= 0:
            _SHARED[key] = value  # an answer cut short by the budget is this lowering's alone
        return value

    call.__name__ = fn.__name__
    call.__doc__ = fn.__doc__
    return call


@_shared
def project(value: Term, steps: tuple) -> Term:
    """The part ``steps`` (``("f", field)``, ``("k", key)``) names of a whole value written to storage."""
    if not steps:
        return value
    kind = value[0]
    if _spent():
        return mk("opaque", "budget:value_steps", (value, mk("const", repr(steps), "string")))
    if kind == "ite":
        return mk_ite(value[1], project(value[2], steps), project(value[3], steps))
    if kind == "load":
        return mk("load", value[1], value[2], (*value[3], *steps))
    if kind == "rawload":
        return mk("opaque", "unsupported:raw_struct", (value,))
    step, rest = steps[0], steps[1:]
    if kind == "struct" and step[0] == "f" and step[1] in value[1]:
        return project(value[2][value[1].index(step[1])], rest)
    if kind == "upd":
        base, inner, written = value[1], value[2], value[3]
        first, deeper = inner[0], inner[1:]
        if first[0] != step[0] or (step[0] == "f" and first[1] != step[1]):
            return project(base, steps)  # another part was written
        hit = TRUE if step[0] == "f" else mk_cmp("eq", step[1], first[1])
        here = written if not deeper else mk("upd", project(base, (step,)), deeper, written)
        return project(mk_ite(hit, here, project(base, (step,))), rest)
    if kind == "array" and step == ("f", "length"):
        return value[1]
    if kind == "array" and step[0] == "k":
        return project(element(value, step[1]), rest)
    if kind == "const" and value[1] == 0:
        return value  # a deleted (zeroed) value: every part of it zero
    return mk("opaque", f"unsupported:part:{kind}", (value, mk("const", repr(steps), "string")))


@_shared
def element(container: Term, key: Term, zero: Term | None = None) -> Term:
    """Item ``key`` of an array value (a memory array, a storage array copied to memory, an argument, an array
    updated in place), in range by the caller's bound. ``zero`` is what an item of a freshly allocated array holds."""
    kind = container[0]
    if _spent():
        return mk("opaque", "budget:value_steps", (container, key))
    if kind == "ite":
        return mk_ite(container[1], element(container[2], key, zero), element(container[3], key, zero))
    if kind == "array" and len(container) == 3:
        items = container[2]
        if key[0] == "const" and isinstance(key[1], int) and not isinstance(key[1], bool):
            return items[key[1]] if 0 <= key[1] < len(items) else unknown("out_of_bounds")
        if not items:
            return unknown("out_of_bounds")
        value = items[-1]
        for i in range(len(items) - 2, -1, -1):
            value = mk_ite(mk_cmp("eq", key, const(i)), items[i], value)
        return value
    if kind == "array":
        return zero if zero is not None else mk("elem", container, key)  # ``new T[](n)``: zeroed
    if kind == "load":
        return mk("load", container[1], container[2], (*container[3], ("k", key)))
    if kind == "upd":
        steps = container[2]
        if steps[0][0] != "k":
            return element(container[1], key, zero)  # its length set: the items are the base's
        hit = mk_cmp("eq", key, steps[0][1])
        inner = (
            container[3] if len(steps) == 1 else mk("upd", element(container[1], key, zero), steps[1:], container[3])
        )
        return mk_ite(hit, inner, element(container[1], key, zero))
    if kind == "const" and container[1] == 0:
        return zero if zero is not None else const(0)
    return mk("elem", container, key)


@_shared
def update(container: Term, key: Term, value: Term) -> Term:
    """``container`` with item ``key`` set to ``value``: item by item where its items are known, else ``upd``."""
    if _spent():
        return mk("opaque", "budget:value_steps", (container, key, value))
    if container[0] == "array" and len(container) == 3:
        items = container[2]
        if key[0] == "const" and isinstance(key[1], int) and not isinstance(key[1], bool):
            if not 0 <= key[1] < len(items):
                return container  # out of range: the bound already ended this path
            return mk("array", container[1], (*items[: key[1]], value, *items[key[1] + 1 :]))
        return mk(
            "array", container[1], tuple(mk_ite(mk_cmp("eq", key, const(i)), value, x) for i, x in enumerate(items))
        )
    if container[0] == "ite":
        return mk_ite(container[1], update(container[2], key, value), update(container[3], key, value))
    return mk("upd", container, (("k", key),), value)


@_shared
def length_of(container: Term) -> Term | None:
    """The length of an array value, ``None`` when it has no term."""
    kind = container[0]
    if _spent():
        return mk("opaque", "budget:value_steps", (container,))
    if kind == "array":
        return container[1]
    if kind == "ite":
        a, b = length_of(container[2]), length_of(container[3])
        return None if a is None or b is None else mk_ite(container[1], a, b)
    if kind == "upd":
        if container[2] == (("f", "length"),):
            return container[3]
        return length_of(container[1])
    if kind == "load":
        return mk("load", container[1], container[2], (*container[3], ("f", "length")))
    if kind == "const" and container[1] == 0:
        return const(0)
    return mk("len", container)


@_shared
def byte_at(container: Term, key: Term) -> Term:
    """Byte ``key`` of a ``bytes`` value: the first byte of the word at that offset (``calldataload``'s word)."""
    kind = container[0]
    if _spent():
        return mk("opaque", "budget:value_steps", (container, key))
    if kind == "ite":
        return mk_ite(container[1], byte_at(container[2], key), byte_at(container[3], key))
    if kind == "upd" and container[2][0][0] == "k":
        return mk_ite(mk_cmp("eq", key, container[2][0][1]), container[3], byte_at(container[1], key))
    if kind == "array" and len(container) == 2:
        return const(0, "bytes1")  # ``new bytes(n)``: zeroed
    return mk_slice(mk("elem", container, key), 0, 1)


def _acted(st: State, call: Term) -> State:
    """``st`` having called out: a mark in its writes, which merges keep per path like any other write."""
    return State(st.pc, st.env, {**st.store, ("act", call, ()): TRUE}, st.ret, halted=st.halted, mem=st.mem)


def _changes(exit_: Exit) -> Term:
    """When a call ending at ``exit_`` has an effect: where it called out (an ``act`` mark), or where a write differs
    from the value it replaces (``if (quorum != MAX) quorum = MAX`` changes nothing once it is MAX)."""
    return mk_or(
        [
            mk_not(mk_cmp("eq", value, unwritten(key)))
            for key, value in exit_.store.items()
            if key[0] not in ("transient", "emit", "heap")
        ]
    )


def unwritten(key: tuple) -> Term:
    if key[0] == "heap":
        return unknown("unallocated")
    if key[0] in ("act", "emit", "havoc"):
        return FALSE  # no call out, no event, no loop's writes on a path that didn't make them
    if key[0] == "transient":
        return mk("const", 0, "uint256")
    if key[0] == "raw":
        return mk("rawload", key[1], key[2])
    return mk("load", key[0], key[1], key[2])


def _merge_ret(states: list[Any]) -> tuple | None:
    rets = [s.ret for s in states]
    if all(r is None for r in rets):
        return None
    width = max(len(r) for r in rets if r is not None)
    columns = [[(r[i] if r is not None and i < len(r) else unknown("no_return")) for r in rets] for i in range(width)]
    return tuple(_select([s.pc for s in states], column) for column in columns)


def _select(pcs: list[Term], values: list[Term]) -> Term:
    items = [_items(v) for v in values]
    if all(i is not None for i in items) and len({v[1] for v in values}) == 1 and len({len(i) for i in items}) == 1:
        # Memory arrays of one length (``uint256[3] words`` set per branch): merged item by item, still an array;
        # memory structs field by field.
        return mk("array", values[0][1], tuple(_select(pcs, list(column)) for column in zip(*items)))
    if all(isinstance(v, tuple) and v and v[0] == "struct" for v in values) and len({v[1] for v in values}) == 1:
        return mk("struct", values[0][1], tuple(_select(pcs, list(column)) for column in zip(*(v[2] for v in values))))
    result = values[-1]
    for pc, value in zip(reversed(pcs[:-1]), reversed(values[:-1])):
        result = mk_ite(pc, value, result)
    return result


def _short_circuits(irs: list[Any]) -> dict[int, tuple[int, Any]]:
    """For each ``||``/``&&`` in a node's IR whose right operand is computed by a contiguous run of operations after
    the left's: the run's start -> (the operator's index, the operator)."""
    produced = {id(ir.lvalue): i for i, ir in enumerate(irs) if getattr(ir, "lvalue", None) is not None}

    def producers(var: Any, before: int) -> set[int]:
        out: set[int] = set()
        stack = [var]
        while stack:
            index = produced.get(id(stack.pop()))
            if index is None or index >= before or index in out:
                continue
            out.add(index)
            stack.extend(getattr(irs[index], "read", None) or [])
        return out

    spans: dict[int, tuple[int, Any]] = {}
    for b, ir in enumerate(irs):
        if not isinstance(ir, Binary) or ir.type not in (BinaryType.OROR, BinaryType.ANDAND):
            continue
        left = producers(ir.variable_left, b)
        right = producers(ir.variable_right, b) - left
        if not right:
            continue
        start = min(right)
        if set(range(start, b)) == right and all(i < start for i in left):
            spans[start] = (b, ir)
        else:
            spans[-1] = (b, ir)  # a right operand interleaved with the left: not separable, see ``_step``
    return spans


class Lowerer:
    """Lowers functions of one contract.

    ``sender`` and ``this`` are what ``msg.sender`` and ``this`` mean in it: the caller and the contract itself at the
    top level, the calling contract and the callee's address when another contract's check is lowered for its caller.
    """

    def __init__(self, contract: Contract, sender: Term = CALLER, this: Term = THIS, code: Term | None = None):
        self.contract = contract
        self.sender = sender
        self.this = this
        self._outer_this = this
        # The address whose code this is, which holds its immutables: ``this``, unless it runs by delegatecall.
        self.code = code if code is not None else this
        self._stack: list[Any] = []
        self._steps = 0
        self._node: Any = None
        self._calldata_min = 4
        self._last_call: Term | None = None
        self._last_returns: int | None = None
        # Memory structs whose fields a reference names (``("sref", id(struct), field)``), by id.
        self._structs: dict[int, Any] = {}
        # Values in memory or calldata whose items a reference names (``("mref", id(holder), key, kind)``), by id.
        self._vars: dict[int, Any] = {}
        # Objects allocated so far (``("heap", n)``), numbered in the order the lowering meets them.
        self._objects = 0
        # Whether the statement being lowered slices calldata in a way Slither's IR drops (``data[4:]``).
        self._sliced = False
        # Whether the call may carry ether: an entry point that isn't payable reverts on any (``success``).
        self._payable = True
        # Ends of the whole call reached inside callees (an assembly ``return``), gathered for the top level.
        self._halts: list = []
        # The arguments this call came with, in order: what ``msg.data[4:]`` encodes.
        self._arguments: tuple = ()
        # Whether some storage write may have gone unrecorded (code not followed, assembly not read).
        self.lost = False
        # Whether assembly read storage this lowering may not place (``sload`` in text it couldn't parse).
        self.raw_reads = False
        self.exits: list = []

    def success(self, function: Function) -> Term:
        """The condition under which an external call to ``function`` returns."""
        self._steps = 0
        args = {id(p): parameter(p, i) for i, p in enumerate(function.parameters)}
        self._calldata_min = _calldata_min(function)
        self._arguments = tuple(args.values())
        self._payable = bool(getattr(function, "payable", True))
        # An enum argument out of its range doesn't decode: the call reverts (Panic 0x21).
        bounds = [
            mk_cmp("lt", args[id(p)], const(count))
            for p in function.parameters
            if (count := _enum_size(getattr(p, "type", None))) is not None
        ]
        exits = self.paths(function, State(mk_and(bounds), args))
        # The calls that do something: a write that may change what storage held, or a call out.
        self.effective = mk_or([mk_and([e.pc, _changes(e)]) for e in exits])
        # (contract, variable) or ("raw", contract) of everything it may write.
        self.written = frozenset(
            ("raw", k[1])
            if k[0] == "raw" or (k[0] == "havoc" and k[2] == "raw")
            else (k[1], k[2])
            if k[0] == "havoc"
            else (k[0], k[1])
            for e in exits
            for k in e.store
            if k[0] not in ("act", "transient", "emit", "heap")
            and not (k[0] == "havoc" and k[2] in ("transient", "*", "*elsewhere"))
        )
        self.exits = exits
        return mk_or([e.pc for e in exits])

    def returns(self, function: Function, args: list[Term], pc: Term = TRUE) -> tuple[Term, tuple]:
        """The condition under which ``function`` returns and its return values, ``args`` bound to its parameters."""
        self._steps = 0
        self._payable = True
        env = {id(p): a for p, a in zip(function.parameters, args)}
        self._arguments = tuple(args)
        exits = self.paths(function, State(pc, env))
        if not exits:
            return FALSE, ()
        merged = merge([State(e.pc, {}, e.store, e.ret) for e in exits])
        return merged.pc, merged.ret or ()

    def called(self, function: Function, args: list[Term], view: bool) -> tuple[Term, tuple]:
        """``returns`` for ``function`` run as a call another contract makes: in its own frame, where ``msg.value`` is
        zero for a view call (a ``staticcall`` carries none) and unknown for an action, and ``msg.data``, ``msg.sig``
        and ``calldatasize`` are the callee's own, never the outer call's. ``args``, ``sender`` and ``this`` stay as
        the caller's terms give them, whatever of the outer frame they read (``check(msg.data)``)."""
        shield: dict[Term, Term] = {}

        def shielded(term: Term, name: str, type_: str) -> Term:
            if not _frame_bound(term):
                return term
            stand_in = mk("arg", f"frame:{name}", type_)
            shield[stand_in] = term
            return stand_in

        given = [shielded(a, str(i), parameter(p, i)[2]) for i, (p, a) in enumerate(zip(function.parameters, args))]
        self.sender = shielded(self.sender, "sender", "address")
        self.this = shielded(self.this, "this", "address")
        if self.code == self._outer_this:
            self.code = self.this
        pc, ret = self.returns(function, given + list(args[len(given) :]))
        signature = function.solidity_signature or f"{function.name}()"
        own = {
            CALLDATA: unknown("callee:msg.data"),
            mk("sig"): const(int.from_bytes(keccak(text=signature)[:4], "big"), "bytes4"),
            mk("callvalue"): const(0) if view else unknown("callee:msg.value"),
        }
        parts = [pc, *(r for r in ret if isinstance(r, Term))]
        for part in parts:
            own.update({t: unknown("callee:calldatasize") for t in subterms(part, "calldatasize")})

        def framed(t: Any) -> Any:
            if not isinstance(t, Term):
                return t
            t = replace_terms(t, own) if contains(t, frozenset({"arg", "sig", "callvalue", "calldatasize"})) else t
            return replace_terms(t, shield) if shield else t

        return framed(pc), tuple(framed(r) for r in ret)

    def _from_here(self, call: Term | None) -> Term | None:
        """A call this code makes, carrying who makes it where that isn't the contract decided: a callee's own calls
        come from the callee (``msg.sender`` there), so they are asked of the chain and lowered from it."""
        if call is None or call[0] != "call" or len(call) > 5 or self.this == THIS:
            return call
        return mk(*call, self.this)

    def paths(self, function: Function, state: State) -> list[Exit]:
        """Each way a call of ``function`` from ``state`` returns, memory left behind: the values it returns read out of
        the objects they point to, its writes storage's alone."""
        out = []
        for e in self.run(function, state, 0):
            heap = State(e.pc, {}, e.store)
            ret = None if e.ret is None else tuple(self._deep(v, heap) for v in e.ret)
            out.append(Exit(e.pc, {k: v for k, v in e.store.items() if k[0] != "heap"}, ret))
        return out

    def run(self, function: Function, state: State, depth: int) -> list[Exit]:
        if depth == 0:
            _STEPS[0] = VALUE_STEPS
        getter = self._getter(function, state) if function.entry_point is None else None
        if getter is not None:
            return [getter]
        if function.entry_point is None or depth > MAX_DEPTH or function in self._stack:
            if depth > 0:
                self.lost = True  # code run without being followed: whatever it writes goes unrecorded
            ret = tuple(unknown(f"unanalysed:{function.canonical_name}") for _ in function.returns)
            return [Exit(mk_and([state.pc, unknown(f"unanalysed:{function.canonical_name}")]), state.store, ret)]
        for r in function.returns:
            state.env.setdefault(id(r), _zero(r.type))
        for v in [*function.parameters, *function.returns]:
            # Memory parameters and return values handed a value (not an object): an object of their own from the
            # start, so every branch below writes into the same one.
            if self._memory_var(v) and not _pointer(state.env.get(id(v))) and not _reference(state.env.get(id(v))):
                state = self._allocate(v, state.env.get(id(v), _zero(v.type)), state)
        self._stack.append(function)
        if depth == 0:
            self._halts = []
        try:
            exits = self._run_from(function, function.entry_point, state, depth)
        finally:
            self._stack.pop()
        if depth == 0:
            exits = [*exits, *self._halts]  # callees that ended the whole call, as this call's own ends
            self._halts = []
        return exits

    def _implementation(self, function: Function, after: Any = None) -> Function | None:
        """The body a call to a bodiless declaration runs in this contract: the first implementation in its
        linearization, or for ``super`` the first past the calling contract (``after``). Slither resolves both within
        the declaring contract's own bases, which can stop at an abstract declaration the deployed contract's order
        passes over (``ERC677Token``'s ``super.transfer`` reaching ``ERC20Basic.transfer``, past ``BasicToken``'s)."""
        order = [self.contract, *self.contract.inheritance]
        start = 0
        if after is not None:
            start = next((i + 1 for i, c in enumerate(order) if c is after), len(order))
        for c in order[start:]:
            for f in c.functions_declared:
                if f.full_name == function.full_name and f.entry_point is not None and not f.is_constructor:
                    return f
        return None

    def _getter(self, function: Function, state: State) -> Exit | None:
        """A body-less declaration that a public state variable implements (an interface's ``fee()`` met by
        ``uint256 public fee``): the variable's getter, returning its storage keyed by the arguments."""
        from slither.core.solidity_types import MappingType

        var = next(
            (v for v in self.contract.state_variables if v.name == function.name and v.visibility == "public"), None
        )
        if var is None:
            return None
        type_ = var.type
        for _ in function.parameters:
            if not isinstance(type_, MappingType):
                return None  # an array's getter reverts past its length
            type_ = type_.type_to
        if function.parameters:
            keys = tuple(("k", self.val(p, state)) for p in function.parameters)
            value = self._read_at((self.this, var.name, keys), state)
        else:
            value = self.val(var, state)
        if len(function.returns) == 1:
            return Exit(state.pc, state.store, (value,))
        return Exit(state.pc, state.store, tuple(unknown(f"getter:{var.name}") for _ in function.returns))

    # Graph walk -------------------------------------------------------------------------------------------------------

    def _run_from(
        self, function: Function, start: Any, state: State, depth: int, body: Any = None, unrolled: int = 0
    ) -> list[Exit]:
        order, edges = _schedule(start)
        incoming: dict[int, list[State]] = {id(start): [state]}
        arrival: dict[int, State] = {}
        exits: list[Exit] = []
        for node in order:
            arrived = incoming.pop(id(node), None)
            if not arrived:
                continue
            st = merge(arrived)
            self._steps += 1
            arrival.setdefault(id(node), st)
            for target, out in self._step(function, node, st, depth, exits, body):
                for succ, kind in edges[id(node)]:
                    if succ is not target:
                        continue
                    if kind != "back":
                        incoming.setdefault(id(succ), []).append(out)
                        continue
                    if succ.type == NodeType.IFLOOP:
                        leave, again = succ.son_false, self._loop_condition(succ, out, depth)
                    else:
                        # ``do { } while (c)``: the condition node's true son is the body, ``out`` already carries
                        # ``c``, and the loop leaves through the condition node's false son.
                        leave, again = (node.son_false if node.type == NodeType.IFLOOP else None), None
                    entry = arrival.get(id(succ))
                    if leave is None or entry is None:
                        exits.append(self._unfollowed(function, out, "unsupported:loop_shape"))
                        continue
                    if again == FALSE:
                        # The loop is done after this iteration: exact, no forgetting.
                        incoming.setdefault(id(leave), []).append(out)
                        continue
                    if again == TRUE and unrolled < MAX_UNROLL and self._steps < UNROLL_BUDGET:
                        # Another iteration whose condition is known: run it, and the rest of the function after it.
                        exits.extend(self._run_from(function, succ, out, depth, body, unrolled + 1))
                        continue
                    more = out
                    if again is not None:
                        # Either the loop stops here, exactly, or it goes on: for a few more iterations exactly, then
                        # with everything it may change forgotten.
                        stop = State(mk_and([out.pc, mk_not(again)]), out.env, out.store, out.ret)
                        incoming.setdefault(id(leave), []).append(stop)
                        more = State(mk_and([out.pc, again]), out.env, out.store, out.ret)
                    if again != TRUE and unrolled < MAX_SYMBOLIC_UNROLL and self._steps < UNROLL_BUDGET:
                        exits.extend(self._run_from(function, succ, more, depth, body, unrolled + 1))
                    else:
                        after, leaving = self._widen(function, more, entry, succ, leave)
                        incoming.setdefault(id(leave), []).append(after)
                        exits.extend(leaving)
        for pending in incoming.values():
            # Nodes the schedule never reached (control flow no loop header explains): unknown, never dropped.
            for st in pending:
                exits.append(self._unfollowed(function, st, "unsupported:irreducible_cfg"))
        return exits

    def _unfollowed(self, function: Function, st: State, label: str) -> Exit:
        """A path this lowering can't follow further: it may return, with unknown values, and write anything."""
        self.lost = True
        ret = None if isinstance(function, Modifier) else tuple(unknown(label) for _ in function.returns)
        return Exit(mk_and([st.pc, unknown(label)]), st.store, ret)

    def _widen(self, function: Function, more: State, entry: State, start: Any, leave: Any) -> tuple[State, list]:
        """The loop entered at ``start`` (its header, or a ``do``'s body) after more iterations than were run: every
        variable and storage its body may write (whatever an iteration that ran left them) is forgotten, from the
        body's own operations, not from what the iterations run happened to change; it leaves through ``leave``, or
        returns from inside with unknown values. The path carries an ``unknown`` conjunct, so it can widen what may
        pass but never proves anything passes."""
        nodes = _loop_nodes(start, leave)
        effects = self._loop_effects(nodes, more)
        changed = [v for k, v in more.env.items() if entry.env.get(k) != v]
        changed += [v for k, v in more.store.items() if entry.store.get(k) != v]
        added = _conjuncts(more.pc) - _conjuncts(entry.pc)
        # A loop whose iterations neither the caller nor the arguments steer (a sum over a stored list) ends the same
        # way whoever calls: its remainder is unknown, but singles out nobody. One the arguments steer but not who
        # calls (running a proposal's calls): how it ends depends on what is asked, never on who asks.
        read = [more.env.get(id(v)) for v in effects["reads"]]
        values = [v for v in [*changed, *added, *read] if isinstance(v, tuple)]
        anyone = not effects["caller"] and not effects["arguments"] and not any(contains(v, _STEERING) for v in values)
        nobody = not effects["caller"] and not any(contains(v, _IDENTITIES) for v in values)
        tag = f"loop:{start.node_id}" + (":anyone" if anyone else ":nobody" if nobody else "")
        steered = () if anyone or nobody else (unknown(tag),)
        owner = getattr(function, "canonical_name", "")

        def forget(label: str, value: Any) -> Term:
            # Which identities it depended on (their presence is what makes it depend on who calls).
            roots: tuple = ()
            if isinstance(value, tuple) and contains(value, _IDENTITIES):
                roots = tuple(
                    root
                    for root, kind in ((CALLER, "caller"), (ORIGIN, "origin"), (unknown(tag), "signer"))
                    if contains(value, frozenset({kind}))
                )
            return mk("opaque", tag, (mk("const", f"{owner}.{label}", "string"), *(roots or steered)))

        env = dict(more.env)
        done = set()
        for var in effects["locals"]:
            env[id(var)] = forget(str(getattr(var, "name", "")), more.env.get(id(var)))
            done.add(id(var))
        for k, v in more.env.items():
            if k not in done and entry.env.get(k) != v:
                env[k] = forget(f"#{len(done)}", v)
                done.add(k)
        # Objects in memory the body may write into, and those they hold: their contents forgotten too.
        objects: set = set()
        pending = [more.env.get(id(var)) for var in effects["objects"]]
        while pending:
            value = pending.pop()
            if not isinstance(value, tuple):
                continue
            for p in subterms(value, "ptr") if isinstance(value, Term) else ():
                if p[1] not in objects:
                    objects.add(p[1])
                    pending.append(more.store.get(("heap", p[1])))
        store: dict = {}
        for k, v in more.store.items():
            if k[0] == "heap" and (k[1] in objects or entry.store.get(k) != v):
                store[k] = mk("opaque", tag, (mk("const", f"{owner}.object{k[1]}", "string"), *steered))
            elif entry.store.get(k) == v or k[0] in ("act", "emit", "havoc", "heap"):
                store[k] = v  # a call out stays made, however many times the loop runs
            else:
                store[k] = mk("opaque", tag, (unwritten(k), *steered))
        marks = [(c, name) for c, name in sorted(effects["storage"], key=repr)]
        if effects["everything"] or effects["elsewhere"]:
            marks.append((self.this, "*" if effects["everything"] else "*elsewhere"))
            # Writes this lowering can't place are lost; code run on this storage elsewhere (a delegatecall, its own
            # entry point again) writes as that code does, which is that code's to account for.
            self.lost = self.lost or effects["everything"]
        if effects["raw"]:
            marks.append((self.this, "raw"))
        if effects["transient"]:
            marks.append((self.this, "transient"))
        for c, name in marks:
            store = stored(store, ("havoc", c, name, tag), TRUE)
        if effects["calls"]:
            store[("act", mk("assumed", f"{tag}:call"), ())] = TRUE
        pc = mk_and([more.pc, unknown(tag)])
        after = State(pc, env, store, more.ret)
        leaving = []
        if effects["halts"]:
            leaving.append(Exit(pc, store, (unknown(tag),), halted=True))  # an assembly ``return`` inside
        if effects["returns"]:
            ret = None
            if not isinstance(function, Modifier):
                ret = tuple(
                    mk("opaque", tag, (mk("const", f"{owner}.return{i}", "string"), *steered))
                    for i in range(len(function.returns))
                )
            leaving.append(Exit(pc, store, ret))
        return after, leaving

    def _loop_effects(self, nodes: list, st: State) -> dict:
        """What the operations of a loop's nodes may write (locals, storage variables, raw or transient slots, or
        anything), whether they call out or return, and whether they read who calls or the arguments."""
        from slither.core.variables.local_variable import LocalVariable

        out: dict = {
            "locals": [],
            "storage": set(),
            "everything": False,
            "elsewhere": False,
            "raw": False,
            "transient": False,
            "calls": False,
            "returns": False,
            "caller": False,
            "arguments": False,
            "reads": [],
            "objects": [],
            "halts": False,
        }
        seen_locals: set = set()
        pointers: list = []

        def local(var: Any) -> None:
            if id(var) not in seen_locals:
                seen_locals.add(id(var))
                out["locals"].append(var)

        def lvalue(var: Any) -> None:
            if isinstance(var, StateVariable):
                if not (var.is_constant or var.is_immutable):
                    out["storage"].add((self.this, var.name))
                return
            if isinstance(var, ReferenceVariable):
                local(var)
                origin = getattr(var, "points_to_origin", None)
                if isinstance(origin, StateVariable):
                    out["storage"].add((self.this, origin.name))
                elif origin is not None and getattr(origin, "is_storage", False):
                    loc = self._location(origin, st)
                    if loc is None:
                        out["everything"] = True
                    else:
                        out["storage"].add((loc[0], loc[1]))
                    pointers.append(origin)
                elif origin is not None:
                    local(origin)
                    out["objects"].append(origin)
                else:
                    out["everything"] = True
                return
            local(var)

        def solidity(name: str) -> None:
            base = name.split("(", 1)[0]
            if base == "sstore":
                out["raw"] = True
            elif base == "tstore":
                out["transient"] = True
            elif base in ("delegatecall", "callcode"):
                out["elsewhere"] = out["raw"] = out["calls"] = True
            elif base in ("call", "create", "create2", "selfdestruct", "suicide"):
                out["calls"] = True
            if base in ("return", "stop", "selfdestruct", "suicide"):
                out["halts"] = True
            if base == "ecrecover":
                out["caller"] = True

        for node in nodes:
            if node.type in (NodeType.RETURN, NodeType.PLACEHOLDER):
                out["returns"] = True
                if node.type == NodeType.PLACEHOLDER:
                    out["everything"] = out["calls"] = True
            if node.type == NodeType.ASSEMBLY and not node.irs and isinstance(getattr(node, "inline_asm", None), str):
                out["everything"] = out["raw"] = out["calls"] = out["returns"] = out["halts"] = True
            for ir in node.irs:
                for var in getattr(ir, "read", None) or []:
                    if isinstance(var, SolidityVariableComposed) and var.name in ("msg.sender", "tx.origin"):
                        out["caller"] = True
                    elif isinstance(var, SolidityVariableComposed) and var.name in ("msg.data", "msg.value"):
                        out["arguments"] = True
                    elif isinstance(var, LocalVariable) and not isinstance(var, ReferenceVariable):
                        out["reads"].append(var)
                if getattr(ir, "lvalue", None) is not None:
                    lvalue(ir.lvalue)
                if isinstance(ir, Delete):
                    lvalue(ir.variable)
                if isinstance(ir, SolidityCall):
                    solidity(ir.function.name)
                elif isinstance(ir, (InternalCall, LibraryCall)) and isinstance(ir.function, Function):
                    self._callee_effects(ir, st, out, local)
                elif isinstance(ir, HighLevelCall):
                    fn = ir.function
                    if not (getattr(fn, "view", False) or getattr(fn, "pure", False)):
                        out["calls"] = True
                    if self.val(ir.destination, st) == self.this:
                        out["elsewhere"] = True  # its own entry point, run again: any of its storage
                elif isinstance(ir, LowLevelCall):
                    out["calls"] = True
                    if str(getattr(ir.function_name, "value", ir.function_name)) == "delegatecall":
                        out["elsewhere"] = out["raw"] = True
                elif isinstance(ir, (Transfer, Send, NewContract)):
                    out["calls"] = True
                elif isinstance(ir, InternalDynamicCall):
                    out["everything"] = out["calls"] = True
        if any(id(p) in seen_locals for p in pointers):
            out["everything"] = True  # a storage pointer moved within the loop: where its writes land isn't known
        return out

    def _callee_effects(self, ir: Any, st: State, out: dict, local: Callable) -> None:
        """What an internal or library call in a loop may write: the state variables its code writes, what it is handed
        by ``storage`` reference, memory it is handed; and whether it calls out or reads who calls."""
        callee = ir.function
        cache = self.__dict__.setdefault("_callee_cache", {})
        if id(callee) not in cache:
            names, raw, transient, everything, calls, caller = set(), False, False, False, False, False
            elsewhere = False
            try:
                names = {v.name for v in callee.all_state_variables_written() if not (v.is_constant or v.is_immutable)}
                reads = {v.name for v in callee.all_solidity_variables_read()}
                caller = bool(reads & {"msg.sender", "tx.origin"})
                for c in callee.all_solidity_calls():
                    base = str(getattr(getattr(c, "function", c), "name", c)).split("(", 1)[0]
                    raw = raw or base == "sstore"
                    transient = transient or base == "tstore"
                    elsewhere = elsewhere or base in ("delegatecall", "callcode")
                    calls = calls or base in ("call", "create", "create2", "selfdestruct", "suicide", "delegatecall")
                    caller = caller or base == "ecrecover"
                for n in callee.all_nodes():
                    if n.type == NodeType.ASSEMBLY and not n.irs and isinstance(getattr(n, "inline_asm", None), str):
                        everything = raw = calls = True
                    for op in n.irs:
                        if isinstance(op, (LowLevelCall, Transfer, Send, NewContract, InternalDynamicCall)):
                            calls = True
                        elif isinstance(op, HighLevelCall) and not isinstance(op, LibraryCall):
                            fn = op.function
                            calls = calls or not (getattr(fn, "view", False) or getattr(fn, "pure", False))
            except Exception as exc:  # a callee Slither can't summarize: anything
                if isinstance(exc, TimeoutError):
                    raise
                everything = raw = calls = caller = True
            cache[id(callee)] = (names, raw, transient, everything, calls, caller, elsewhere)
        names, raw, transient, everything, calls, caller, elsewhere = cache[id(callee)]
        out["elsewhere"] = out["elsewhere"] or elsewhere
        out["storage"].update((self.this, n) for n in names)
        out["raw"] = out["raw"] or raw
        out["transient"] = out["transient"] or transient
        out["everything"] = out["everything"] or everything
        out["calls"] = out["calls"] or calls
        out["caller"] = out["caller"] or caller
        for p, a in zip(callee.parameters, ir.arguments):
            if getattr(p, "location", None) == "storage":
                loc = self._location(a, st)
                if loc is None:
                    out["everything"] = True
                else:
                    out["storage"].add((loc[0], loc[1]))
            elif not isinstance(a, (Constant, StateVariable)) and _reference_typed(getattr(p, "type", None)):
                local(a)  # memory handed by reference: the callee may write into it
                out["objects"].append(a)

    def _loop_condition(self, header: Any, st: State, depth: int) -> Term:
        """The header's condition evaluated in ``st``, or ``None`` when it isn't a loop header."""
        if header.type != NodeType.IFLOOP:
            return unknown("not_a_loop")
        self._node = header
        bad, cuts = _sliced(header)
        self._sliced = bad or bool(cuts)
        for ir in header.irs:
            if isinstance(ir, Condition):
                return self.val(ir.value, st)
            st = self._exec(ir, st, depth)
        return unknown("no_condition")

    def _step(self, function: Function, node: Any, st: State, depth: int, exits: list[Exit], body: Any):
        """Run one node; yield (successor, state) pairs. Exits and dead paths yield nothing."""
        self._node = node
        self._sliced, cuts = _sliced(node)
        for base, size in cuts:
            if base == "msg.data":
                continue  # at least the selector's four bytes, or the call wouldn't be here
            held = next((v for v in [*function.parameters, *function.variables] if v.name == base), None)
            if held is None:
                self._sliced = True
                break
            # ``bytesN(x[:N])`` reverts unless ``x`` holds N bytes.
            length = self._length(self.val(held, st), getattr(held, "type", None))
            st = replace(st, pc=mk_and([st.pc, mk_cmp("le", const(size), length)]))
        if node.type == NodeType.THROW:
            return
        declared = getattr(node, "variable_declaration", None)
        if node.type == NodeType.VARIABLE and not node.irs and declared is not None and self._memory_var(declared):
            # ``S memory s;``: a fresh zeroed object each time the declaration runs.
            st = self._allocate(declared, _zero(declared.type), st)
        if node.type == NodeType.PLACEHOLDER and body is not None:
            # A modifier's ``_``: the rest of the function, then the modifier's own tail with its locals.
            for done in body(st):
                if done.halted:
                    exits.append(done)  # the function ended the whole call: the modifier's tail never runs
                    continue
                after = State(done.pc, st.env, done.store, done.ret)
                if node.sons:
                    yield from self._succeed(node, after, node.sons)
                else:
                    exits.append(Exit(after.pc, after.store, after.ret))
            return
        if node.type == NodeType.ASSEMBLY and not node.irs and isinstance(getattr(node, "inline_asm", None), str):
            st = self._legacy_assembly(function, node.inline_asm, st)
            if st.halted:
                exits.append(Exit(st.pc, st.store, st.ret, halted=True))
                return
            yield from self._succeed(node, st, node.sons)
            return
        if node.type == NodeType.TRY:
            # The call and its result's bindings are on this node; the first son is the success clause, the rest
            # catch clauses, one of which runs when the callee itself reverts. A failure in this contract (no code at
            # the target, undecodable return data) is caught by neither: the whole call reverts.
            self._last_call = None
            after = st
            for ir in node.irs:
                after = self._exec(ir, after, depth)
                if after.pc == FALSE:
                    break
            call = self._last_call
            ok = mk("ok", call, self._last_returns) if call is not None else unknown(f"try:{node.node_id}")
            caught = mk("caught", call, self._last_returns) if call is not None else unknown(f"catch:{node.node_id}")
            if node.sons:
                yield node.sons[0], State(mk_and([after.pc, ok]), after.env, after.store, after.ret)
            catches = node.sons[1:]
            for i, son in enumerate(catches):
                which = TRUE if len(catches) == 1 else unknown(f"catch:{node.node_id}:{i}")  # by the revert data
                yield son, State(mk_and([st.pc, caught, which]), dict(st.env), st.store, st.ret)
            return
        cond: Term | None = None
        custom = self._require_with_error(node, st)
        if custom is not None:
            # Slither lowers ``require(cond, Error())`` to an unconditional revert; the expression keeps the condition.
            st = replace(st, pc=mk_and([st.pc, custom]))
            if st.pc == FALSE:
                return
        # With ``require(bool,error)`` in the IR, the ``revert Error()`` before it only builds its argument.
        error_argument = _has_require_with_error(node)
        irs = list(node.irs) if custom is None else []
        spans = _short_circuits(irs)
        if -1 in spans:
            # An operand that runs only when the other doesn't decide, its operations not separable from the rest:
            # whether they run (a call, a check) is unknown.
            st = replace(st, pc=mk_and([st.pc, unknown("unsupported:short_circuit")]))
        skip_to = 0
        for index, ir in enumerate(irs):
            if index < skip_to:
                continue
            if index in spans:
                # The right operand of ``||``/``&&`` runs only when the left doesn't decide: its calls and checks
                # hold on that branch alone (Slither's IR evaluates both sides).
                skip_to, binary = spans[index]
                st = self._short_circuit(irs[index:skip_to], binary, st, depth)
                if st.pc == FALSE:
                    return
                continue
            if error_argument and isinstance(ir, SolidityCall) and ir.function.name.startswith("revert "):
                continue
            if isinstance(ir, InternalCall) and isinstance(ir.function, Modifier):
                rest = node.sons[0] if node.sons else None
                exits.extend(self._modifier(function, ir, st, depth, rest))
                return
            if isinstance(ir, Return):
                values = tuple(self._returned(function, i, v, st) for i, v in enumerate(ir.values))
                if len(values) == 1 and len(function.returns) > 1:
                    # ``return f(...)`` handing on another function's several values.
                    values = tuple(_item(values[0], i) for i in range(len(function.returns)))
                exits.append(Exit(st.pc, st.store, values))
                return
            if isinstance(ir, Condition):
                cond = self.val(ir.value, st)
                continue
            st = self._exec(ir, st, depth)
            if st.pc == FALSE:
                return
            if st.halted:
                exits.append(Exit(st.pc, st.store, st.ret, halted=True))
                return
        if node.type in (NodeType.IF, NodeType.IFLOOP) and cond is not None:
            if node.son_true is not None:
                yield node.son_true, replace(st, pc=mk_and([st.pc, cond]))
            if node.son_false is not None:
                yield node.son_false, replace(st, pc=mk_and([st.pc, mk_not(cond)]))
            return
        if not node.sons:
            ret = st.ret if st.ret is not None else tuple(self._value(r, st) for r in function.returns)
            exits.append(Exit(st.pc, st.store, ret))
            return
        yield from self._succeed(node, st, node.sons)

    def _arithmetic(self, ir: Binary, a: Term, b: Term) -> tuple[Term, list]:
        """An arithmetic operation in its operands' type: a narrower type wraps at its own width, a signed one
        divides, shifts and compares as signed; checked arithmetic (Solidity >= 0.8 outside ``unchecked``) reverts
        out of range, and Solidity's division and remainder by zero always (Panic 0x11, 0x12): those are conditions
        on the path. Yul's arithmetic is unchecked, 256-bit, and divides by zero to zero."""
        op = _BINARY.get(ir.type)
        if op is None:
            return unknown(f"unsupported:binary:{ir.type}"), []
        node = self._node
        yul = bool(getattr(getattr(node, "scope", None), "is_yul", False))
        bits, is_signed = _integer(_operand_type(ir))
        conditions: list = []
        if op in ("div", "mod") and not yul:
            conditions.append(mk_not(mk_cmp("eq", b, const(0))))
        constants = isinstance(ir.variable_left, Constant) and isinstance(ir.variable_right, Constant)
        checked = (
            op in ("add", "sub", "mul", "pow")
            and not yul
            and not constants  # literals are folded by the compiler, rationally: never a runtime overflow
            and bool(getattr(getattr(node, "scope", None), "is_checked", False))
            and _checked_version(self.contract)
        )
        if is_signed:
            name = f"int{bits}"
            x = _convert(name, a)
            y = b if op in ("shl", "shr", "pow") else _convert(name, b)
            value = _convert(name, mk_op({"div": "sdiv", "mod": "smod", "shr": "sar"}.get(op, op), (x, y)))
        else:
            x, y = a, b
            value = mk_op(op, (a, b))
            if bits < 256 and not checked and op in ("add", "sub", "mul", "pow", "shl"):
                value = _convert(f"uint{bits}", value)  # wraps at its own width
        if checked and op == "sub" and not is_signed:
            conditions.append(mk_cmp("le", y, x))  # an unsigned difference in range: exactly ``b <= a``
        elif checked:
            conditions.append(mk_op("fits", (const(op, "string"), x, y, const(bits), const(is_signed, "bool"))))
        return value, conditions

    def _short_circuit(self, irs: list[Any], binary: Any, st: State, depth: int) -> State:
        left = self.val(binary.variable_left, st)
        guard = mk_not(left) if binary.type == BinaryType.OROR else left
        ran = replace(st, pc=mk_and([st.pc, guard]))
        spans = _short_circuits(irs)
        if -1 in spans:
            ran = replace(ran, pc=mk_and([ran.pc, unknown("unsupported:short_circuit")]))
        skip_to = 0
        for index, ir in enumerate(irs):
            if index < skip_to or ran.pc == FALSE:
                continue
            if index in spans:
                skip_to, inner = spans[index]
                ran = self._short_circuit(irs[index:skip_to], inner, ran, depth)
                continue
            ran = self._exec(ir, ran, depth)
        if ran.pc != FALSE:
            # The operand as a value: a storage reference (``isAdmin[msg.sender]``) means nothing once merged.
            env = dict(ran.env)
            env[id(binary.variable_right)] = self.val(binary.variable_right, ran)
            ran = replace(ran, env=env)
        skipped = replace(st, pc=mk_and([st.pc, mk_not(guard)]))
        live = [x for x in (ran, skipped) if x.pc != FALSE]
        if not live:
            return State(FALSE, st.env, st.store, st.ret)
        merged = merge(live)
        return State(merged.pc, merged.env, merged.store, st.ret)

    def _succeed(self, node: Any, st: State, sons: list[Any]):
        if not sons:
            return
        for son in sons:
            yield son, st

    def _modifier(self, function: Function, ir: InternalCall, st: State, depth: int, rest: Any) -> list[Exit]:
        modifier = ir.function
        assert isinstance(modifier, Modifier)
        caller_env = st.env

        def body(at: State) -> list[Exit]:
            inner = State(at.pc, caller_env, at.store, at.ret)
            if rest is None:
                ret = tuple(self._value(r, inner) for r in function.returns)
                return [Exit(at.pc, at.store, ret)]
            return self._run_from(function, rest, inner, depth)

        env = {id(p): self.val(a, st) for p, a in zip(modifier.parameters, ir.arguments)}
        if modifier.entry_point is None or depth > MAX_DEPTH:
            self.lost = True  # whatever the modifier writes goes unrecorded
            return body(State(mk_and([st.pc, unknown(f"unanalysed:{modifier.canonical_name}")]), {}, st.store))
        out = self._run_from(modifier, modifier.entry_point, State(st.pc, env, st.store, None), depth + 1, body)
        # A modifier that returns before ``_`` returns the function's defaults.
        defaults = tuple(_zero(r.type) for r in function.returns)
        return [Exit(e.pc, e.store, e.ret if e.ret is not None else defaults, e.halted) for e in out]

    # Operations -------------------------------------------------------------------------------------------------------

    def _exec(self, ir: Any, st: State, depth: int) -> State:
        for var in getattr(ir, "read", None) or []:
            # A value in memory read through a variable first gets an object, so every later name for it is that one.
            if self._memory_var(var):
                held = st.env.get(id(var))
                if not _pointer(held) and not _reference(held):
                    st = self._allocate(var, held if held is not None else _zero(var.type), st)
        out = self._exec_ir(ir, st, depth)
        if out.mem and not _keeps_memory(ir):
            out = replace(out, mem=())
        return out

    def _exec_ir(self, ir: Any, st: State, depth: int) -> State:
        if isinstance(ir, SolidityCall):
            return self._solidity_call(ir, st)
        if isinstance(ir, (InternalCall, LibraryCall)) and isinstance(ir.function, Function):
            # A ``storage`` parameter is the caller's location, not a copy (``EnumerableSet.contains(set, x)``).
            # A ``memory`` one is the caller's object, which the callee may write into.
            args = [
                ("loc", loc)
                if getattr(p, "location", None) == "storage" and (loc := self._location(a, st)) is not None
                else self._value(a, st)
                if self._memory_var(p)
                else self.val(a, st)
                for p, a in zip(ir.function.parameters, ir.arguments)
            ]
            env = {id(p): a for p, a in zip(ir.function.parameters, args)}
            target = ir.function
            if target.entry_point is None and isinstance(ir, InternalCall):
                written = str(getattr(self._node, "expression", "") or "")
                above = (
                    self._stack[-1].contract_declarer if f"super.{target.name}(" in written and self._stack else None
                )
                target = self._implementation(target, above) or target
            node, sliced = self._node, self._sliced
            try:
                exits = self.run(target, State(st.pc, env, st.store), depth + 1)
            finally:
                self._node, self._sliced = node, sliced  # the rest of this statement is this statement's
            # A callee that ends the whole call (an assembly ``return``) ends it here too: not a return to this caller.
            self._halts.extend(e for e in exits if e.halted)
            exits = [e for e in exits if not e.halted]
            if not exits:
                return State(FALSE, st.env, st.store, st.ret)
            done = merge([State(e.pc, {}, e.store, e.ret) for e in exits])
            out = State(done.pc, dict(st.env), done.store, st.ret)
            if ir.lvalue is not None:
                ret = done.ret or ()
                out.env[id(ir.lvalue)] = ret[0] if len(ret) == 1 else ("tuple", ret)
            return out
        if isinstance(ir, Assignment):
            if self._yul_sload_of_constant(ir.rvalue):
                # Slither lowers Yul ``sload(SLOT)`` of a constant to the constant itself (Solady ``Ownable``).
                return self._write(ir.lvalue, mk("rawload", self.this, self.val(ir.rvalue, st)), st)
            if getattr(ir.lvalue, "is_storage", False) and (loc := self._location(ir.rvalue, st)) is not None:
                return self._bind(ir.lvalue, ("loc", loc), st)  # a storage pointer names a location
            if getattr(ir.lvalue, "is_storage", False) and str(getattr(ir.rvalue, "type", "")) in (
                "bytes32",
                "uint256",
            ):
                # ``$.slot := LOCATION`` (namespaced storage, OZ 5): the pointer is the struct rooted at that slot.
                root = mk("slot", self.val(ir.rvalue, st), str(getattr(ir.lvalue, "type", "")))
                return self._bind(ir.lvalue, ("loc", (self.this, root, ())), st)
            # A value memory holds by reference names the same object (``b = a``); storage takes a copy (``_write``).
            return self._write(ir.lvalue, self._value(ir.rvalue, st), st)
        if isinstance(ir, Delete):
            # ``delete m[k]``: Slither's lvalue is ``m`` itself; the entry cleared is ``variable`` (an item or field in
            # memory likewise).
            held = st.env.get(id(ir.variable))
            target = ir.variable if self._location(ir.variable, st) is not None or _reference(held) else ir.lvalue
            return self._write(target, _zero(getattr(target, "type", None)), st)
        if isinstance(ir, Binary):
            a, b = self.val(ir.variable_left, st), self.val(ir.variable_right, st)
            if ir.type == BinaryType.ANDAND:
                value = mk_and([a, _ran_under(b, a)])
            elif ir.type == BinaryType.OROR:
                value = mk_or([a, _ran_under(b, mk_not(a))])
            elif ir.type in _COMPARE:
                bits, is_signed = _integer(_operand_type(ir))
                if is_signed:
                    # Compared as the signed numbers they are (Yul's ``slt``/``sgt`` too, as Slither renders them).
                    a, b = _convert(f"int{bits}", a), _convert(f"int{bits}", b)
                value = mk_cmp(_COMPARE[ir.type], a, b)
            else:
                value, conditions = self._arithmetic(ir, a, b)
                if conditions:
                    st = replace(st, pc=mk_and([st.pc, *conditions]))
            return self._write(ir.lvalue, value, st)
        if isinstance(ir, Unary):
            a = self.val(ir.rvalue, st)
            if ir.type == UnaryType.BANG:
                return self._write(ir.lvalue, mk_not(a), st)
            # ``~x`` flips the bits of ``x``'s own width.
            type_ = str(getattr(ir.rvalue, "type", "") or "")
            flipped = mk_op("bnot", (a,))
            return self._write(ir.lvalue, flipped if type_ in ("uint256", "bytes32") else _convert(type_, flipped), st)
        if isinstance(ir, TypeConversion):
            source = getattr(ir.variable, "type", None)
            value = _convert(str(ir.type), self.val(ir.variable, st), source)
            count = _enum_size(ir.type)
            if count is not None:
                # A number converted to an enum it has no member for reverts (Panic 0x21).
                st = replace(st, pc=mk_and([st.pc, mk_cmp("lt", self.val(ir.variable, st), const(count))]))
            return self._write(ir.lvalue, value, st)
        if isinstance(ir, Index):
            return self._index(ir, st)
        if isinstance(ir, Member):
            return self._member(ir, st)
        if isinstance(ir, (NewArray, NewElementaryType)):
            # ``new T[](n)``, ``new bytes(n)``: n zeroed items, whose length is what code reads back. A length past
            # 2**64 - 1 reverts (Panic 0x41).
            length = self.val(ir.arguments[0], st) if ir.arguments else unknown("array_length")
            st = replace(st, pc=mk_and([st.pc, mk_cmp("lt", length, const(2**64))]))
            fresh = _new_array(length) if isinstance(ir, NewArray) else mk("array", length)
            return self._write(ir.lvalue, fresh, st)
        if isinstance(ir, NewStructure):
            # ``S(a, b)``: its fields by name, so reading one back gives what was put there.
            names = tuple(m.name for m in ir.structure.elems_ordered)
            values = tuple(self._value(a, st) for a in ir.arguments)
            if len(names) == len(values):
                return self._write(ir.lvalue, mk("struct", names, values), st)
            # A struct holding a mapping, built without it: which argument is which field isn't placed.
            return self._write(ir.lvalue, unknown("unsupported:NewStructure"), st)
        if isinstance(ir, InitArray):
            if len(ir.init_values) == 1 and getattr(ir.lvalue, "location", None) == "storage":
                # ``T[] storage list = s.items``, which Slither renders as an array literal: a pointer to storage.
                pointed = self._location(ir.init_values[0], st)
                if pointed is not None:
                    return self._bind(ir.lvalue, ("loc", pointed), st)
            # Slither renders both ``T[] memory xs = ys`` (a copy) and ``[a, b]`` (a literal) as an array literal; the
            # ranks tell them apart: a copy is an array of the same rank, a literal's items have one fewer.
            rank = _rank(getattr(ir.lvalue, "type", None))
            ranks = {_rank(getattr(v, "type", None)) for v in ir.init_values}
            if len(ir.init_values) == 1 and rank is not None and ranks == {rank}:
                return self._write(ir.lvalue, self._value(ir.init_values[0], st), st)
            if rank is None or ranks != {rank - 1}:
                return self._write(ir.lvalue, unknown("unsupported:InitArray"), st)
            values = [self._value(v, st) for v in ir.init_values]
            return self._write(ir.lvalue, mk("array", const(len(values), "uint256"), tuple(values)), st)
        if isinstance(ir, Length):
            type_ = getattr(ir.value, "type", None)
            base = self._location(ir.value, st)
            if base is not None:
                if _bytes_typed(type_):
                    # A ``bytes``/``string`` in storage keeps its length in its encoding: read off the value.
                    return self._write(ir.lvalue, mk("len", self._read_at(base, st)), st)
                # A storage array's length is a slot of its own, read and (before solc 0.6, ``a.length++``) written
                # through this reference.
                return self._bind(ir.lvalue, ("loc", _extend(base, ("f", "length"))), st)
            held = self.val(ir.value, st)
            if held[0] == "code":
                return self._write(ir.lvalue, mk("codesize", held[1]), st)
            fixed = _fixed_length(type_)
            if fixed is not None:
                return self._write(ir.lvalue, const(fixed), st)
            return self._write(ir.lvalue, self._length(held, type_), st)
        if isinstance(ir, CodeSize):
            return self._write(ir.lvalue, mk("codesize", self.val(ir.value, st)), st)  # ``a.code.length``
        if isinstance(ir, EventCall):
            # An event, as a mark in the writes like a call out: which writes each path logs (``write_log``).
            args = tuple(self.val(a, st) for a in ir.arguments)
            return State(st.pc, st.env, {**st.store, ("emit", str(ir.name), args): TRUE}, st.ret, mem=st.mem)
        if isinstance(ir, HighLevelCall) and not isinstance(ir, LibraryCall):
            return self._external_call(ir, st)
        if isinstance(ir, Unpack):
            whole = self._value(ir.tuple, st)
            item = _item(whole, ir.index)
            return self._write(ir.lvalue, item, st)
        if isinstance(ir, (Transfer, Send)):
            st = _acted(st, mk("assumed", f"value:{id(ir)}"))
            lvalue = getattr(ir, "lvalue", None)  # ``Send`` returns a bool, ``Transfer`` nothing
            return self._write(lvalue, unknown(type(ir).__name__), st) if lvalue is not None else st
        if isinstance(ir, LowLevelCall):
            st = _acted(st, mk("assumed", f"lowlevel:{id(ir)}"))
            if ir.lvalue is None:
                return st
            name = str(getattr(ir.function_name, "value", ir.function_name))
            target = self.val(ir.destination, st)
            data = self.val(ir.arguments[0], st) if ir.arguments else CALLDATA
            inputs = (target, *(self.val(a, st) for a in ir.arguments))
            if name == "delegatecall":
                # Forwarding this call's own data (a proxy), or calling something else with data of its own: code
                # run on this storage, which reads unknown after it.
                success = mk("delegate", target) if data == CALLDATA else mk("delegate", target, data)
                returned = mk("opaque", "returndata", inputs)
                st = replace(st, store=stored(st.store, ("havoc", self.this, "*elsewhere", "delegatecall"), TRUE))
            elif name == "staticcall":
                # A query, not an action: the view call its data encodes, or unknown.
                call = self._encoded_call(target, data, True)
                if call is None:
                    label = "unsupported:staticcall"
                    st = replace(st, pc=mk_and([st.pc, unknown(label)])) if contains(data, IDENTITY_KINDS) else st
                    success, returned = unknown(label), unknown(label)
                else:
                    success, returned = mk("ok", call, None), mk("opaque", "returndata", (call,))
            else:
                # An action the caller arranges, like a transfer; one handed the caller is the action its data
                # encodes, so the callee's own check of who that is counts (an unreadable one: unknown).
                action = self._encoded_call(target, data, False)
                if action is not None:
                    success = mk("ok", action, None)
                    st = _acted(st, action)
                elif contains(data, IDENTITY_KINDS):
                    success = unknown("unsupported:call_data")
                else:
                    success = mk("assumed", name)
                returned = mk("assumed", "returndata")  # what an arranged action returns is arranged with it
            return self._write(ir.lvalue, ("tuple", (success, returned)), st)
        if isinstance(ir, NewContract):
            # Code deployed by this call: an effect whatever the new contract's constructor does, an action the caller
            # arranges like any call out, unless it hands the constructor who calls.
            st = _acted(st, mk("assumed", f"create:{id(ir)}"))
            if any(contains(self.val(a, st), IDENTITY_KINDS) for a in ir.arguments):
                st = replace(st, pc=mk_and([st.pc, unknown("unsupported:NewContract")]))
            return self._write(ir.lvalue, unknown("created"), st) if ir.lvalue is not None else st
        if isinstance(ir, Nop):
            return st
        label = REJECTED_OPERATIONS.get(type(ir).__name__)
        if label is None and type(ir).__name__ not in HANDLED_OPERATIONS:
            label = f"unsupported:{type(ir).__name__}"
        if label is not None:
            # An operation not lowered (a call through a function pointer): the path, what it writes and what it
            # returns, all unknown by name.
            self.lost = True
            st = _acted(replace(st, pc=mk_and([st.pc, unknown(label)])), mk("assumed", label))
            lvalue = getattr(ir, "lvalue", None)
            return self._write(lvalue, unknown(label), st) if lvalue is not None else st
        return st

    def _solidity_call(self, ir: SolidityCall, st: State) -> State:
        name = ir.function.name
        base = name.split("(", 1)[0]
        args = [self.val(a, st) for a in ir.arguments]
        # ``revert Error(...)`` names the custom error it reverts with: one builtin, ``revert ``.
        known = "revert " if name.startswith("revert ") else name
        rejected = REJECTED_BUILTINS.get(known, None if known in HANDLED_BUILTINS else f"unsupported:{name}")
        if rejected is not None:
            if name in _VYPER or known not in REJECTED_BUILTINS:
                # Semantics not this lowering's (a call out that reverts on failure, bounds): the path itself unknown.
                self.lost = True
                st = _acted(replace(st, pc=mk_and([st.pc, unknown(rejected)])), mk("assumed", rejected))
                return self._write(ir.lvalue, unknown(rejected), st) if ir.lvalue is not None else st
            # A value of the environment, the same for every caller: unknown by name.
            return self._write(ir.lvalue, mk("opaque", rejected, tuple(args)), st) if ir.lvalue is not None else st
        if base in ("addmod", "mulmod") and not getattr(getattr(self._node, "scope", None), "is_yul", False):
            # Solidity's form reverts on a zero modulus (Panic 0x12, since 0.5); Yul's returns zero.
            version = str(getattr(self.contract.compilation_unit, "solc_version", "") or "")
            parts = [int(x) for x in version.split(".")[:2] if x.isdigit()]
            if len(parts) == 2 and parts >= [0, 5] and len(args) == 3:
                st = replace(st, pc=mk_and([st.pc, mk_not(mk_cmp("eq", args[2], const(0)))]))
        if base in _YUL_ENVIRONMENT and not args:
            value = _YUL_ENVIRONMENT[base] if base != "callvalue" or self._payable else const(0)
            return self._write(ir.lvalue, value, st) if ir.lvalue is not None else st
        if base in ("address", "caller", "codesize", "this.balance") and not args:
            value = {"address": self.this, "caller": self.sender, "codesize": mk("codesize", self.code)}.get(
                base, mk("balance", self.this)
            )
            return self._write(ir.lvalue, value, st) if ir.lvalue is not None else st
        packed_v = (
            base == "byte"
            and len(args) == 2
            and _small_const(args[0]) == 0
            and args[1][:2] == ("opaque", "mload(uint256)")
        )
        if base in ("byte", "signextend", "clz") and not packed_v:
            value = mk_op(base, tuple(args))
            return self._write(ir.lvalue, value, st) if ir.lvalue is not None else st
        if base in ("bytes.concat", "string.concat"):
            # The same bytes ``abi.encodePacked`` makes of them.
            value = mk("enc", "abi.encodePacked", tuple(args))
            return self._write(ir.lvalue, value, st) if ir.lvalue is not None else st
        if base == "codehash" and len(args) == 1:
            return self._write(ir.lvalue, mk("codehash", args[0]), st) if ir.lvalue is not None else st
        if base in ("require", "assert"):
            return replace(st, pc=mk_and([st.pc, args[0]]))  # a condition leaves memory as it was
        if base.startswith("revert") or base == "invalid":
            return State(FALSE, st.env, st.store, st.ret)
        if base in ("selfdestruct", "suicide"):
            # Ends the call successfully, sending the contract's ether away: an effect, not a refusal.
            acted = _acted(st, mk("assumed", "selfdestruct"))
            return State(acted.pc, acted.env, acted.store, st.ret, halted=True, mem=st.mem)
        if base in ("return", "stop"):
            # Assembly ``return(p, n)`` ends the whole call successfully (a proxy forwarding its delegate's result).
            ret = st.ret if st.ret is not None else (unknown("assembly_return"),)
            return State(st.pc, st.env, st.store, ret, halted=True)
        if base == "abi.encodeCall" and len(ir.arguments) == 2 and isinstance(ir.arguments[1], list):
            # ``abi.encodeCall(I.f, (a, b))``: the same bytes as ``abi.encodeWithSignature("f(...)", a, b)``.
            function = args[0]
            if function[0] == "const" and function[2] == "function":
                inputs = tuple(self.val(a, st) for a in ir.arguments[1])
                value = mk("enc", "abi.encodeWithSignature", (const(function[1], "string"), *inputs))
                return self._write(ir.lvalue, value, st) if ir.lvalue is not None else st
        if base in ("log0", "log1", "log2", "log3", "log4") and len(args) >= 2:
            # An event written in assembly (DSS's ``note``): a mark like ``emit``'s, its topics as the arguments.
            topics = tuple(mk("sig") if _selector_word(t) else t for t in args[2:])
            return State(st.pc, st.env, {**st.store, ("emit", base, topics): TRUE}, st.ret, mem=st.mem)
        if base == "staticcall" and len(args) == 6:
            return self._static_call(ir, args, st)
        if base == "call" and len(args) == 7:
            action = self._from_here(_encoded_action(args[1], args[3], args[2])) or self._scratch_action(st.mem, args)
            out, size = _small_const(args[5]), _small_const(args[6])
            if action is not None and out is not None and size is not None and size % 32 == 0:
                # ``call(gas, token, 0, add(data, 0x20), mload(data), out, size)`` of ``abi.encodeCall`` data
                # (OpenZeppelin's ``SafeERC20``): the action that data names, its return words left at ``out``.
                written = {out + 32 * i: mk("item", action, i) for i in range(size // 32)}
                mem = (*((o, w) for o, w in st.mem if not out - 31 <= o < out + size), *written.items())
                acted = _acted(State(st.pc, st.env, st.store, st.ret, mem=mem), action)
                after = State(acted.pc, acted.env, acted.store, acted.ret, mem=mem)
                self._last_call, self._last_returns = action, None  # what ``returndatasize()`` asks about next
                return self._write(ir.lvalue, mk("ok", action, None), after) if ir.lvalue is not None else after
        if base in ("call", "callcode"):
            # Assembly ``call(gas, to, value, in, size, out, outsize)``: an action the caller arranges, like a
            # low-level ``.call``, and so is what it returns (Solady's ``safeTransferFrom`` reading ``mload(0) == 1``).
            out, size = (_small_const(args[5]), _small_const(args[6])) if len(args) == 7 else (None, None)
            mem: tuple = ()
            if out is not None and size is not None and size % 32 == 0:
                kept = tuple((o, w) for o, w in st.mem if not out - 31 <= o < out + size)
                mem = (*kept, *((out + 32 * i, mk("assumed", "returndata")) for i in range(size // 32)))
            after = _acted(State(st.pc, st.env, st.store, st.ret, mem=mem), mk("assumed", base))
            # Data this reading couldn't decode that holds who calls: the callee's check of that caller is unread.
            start, length = (_small_const(args[3]), _small_const(args[4])) if len(args) == 7 else (None, None)
            named = (
                start is not None
                and length is not None
                and any(
                    start - 31 <= o < start + length and contains(w, IDENTITY_KINDS)
                    for o, w in st.mem
                    if isinstance(w, tuple)
                )
            )
            success = unknown("unsupported:call_data") if named else mk("assumed", base)
            return self._write(ir.lvalue, success, after) if ir.lvalue is not None else after
        if base == "delegatecall":
            # ``delegatecall(gas, target, ...)``: the target's code for this call, on this storage, for this caller;
            # an effect whether or not its success is used.
            value = mk("delegate", args[1] if len(args) > 1 else unknown("delegate_target"))
            st = _acted(st, mk("assumed", "delegatecall"))
            st = replace(st, store=stored(st.store, ("havoc", self.this, "*elsewhere", "delegatecall"), TRUE))
            return self._write(ir.lvalue, value, st) if ir.lvalue is not None else st
        if base in ("create", "create2"):
            # Assembly ``create``: code deployed by this call, like ``new C()``.
            st = _acted(st, mk("assumed", base))
            return self._write(ir.lvalue, unknown("created"), st) if ir.lvalue is not None else st
        if base == "returndatacopy" and len(args) == 3:
            # The last call's return data copied out: its first word, when that call is known and copied from the
            # start (GPv2's ``returndatacopy(0, 0, returndatasize())`` before ``mload(0)``); else memory unknown.
            dest = _small_const(args[0])
            if dest is None or self._last_call is None or _small_const(args[1]) != 0:
                return State(st.pc, st.env, st.store, st.ret)
            kept = tuple((o, w) for o, w in st.mem if not dest - 31 <= o < dest + 32)
            return State(st.pc, st.env, st.store, st.ret, mem=(*kept, (dest, mk("item", self._last_call, 0))))
        if base == "mstore" and len(args) == 2:
            offset = _small_const(args[0])
            mem = (*st.mem, (offset, args[1])) if offset is not None else ()
            return State(st.pc, st.env, st.store, st.ret, mem=mem)
        if base == "mload" and len(args) == 1:
            value = (
                _memory_word(st.mem, _small_const(args[0]))
                or _packed_item(args[0], 32)
                or (const(_FREE_MEMORY) if _small_const(args[0]) == 0x40 else None)
                or _lost_word(name, args)
            )
        elif (
            base == "byte"
            and len(args) == 2
            and _small_const(args[0]) == 0
            and args[1][:2] == ("opaque", "mload(uint256)")
        ):
            # ``byte(0, mload(add(sig, 0x60)))``: the one-byte item a packed encoding put there (a signature's ``v``).
            value = _packed_item(args[1][2][0], 1) or mk("opaque", name, tuple(args))
        elif base in _HASHES:
            if "bytes" in name or "()" in name:
                inputs = tuple(args)
            else:
                # The assembly form hashes a memory range: the bytes earlier ``mstore``s left there, when known.
                packed = _memory_bytes(st.mem, *(_small_const(a) for a in args[:2])) if len(args) == 2 else None
                inputs = (mk("enc", "abi.encodePacked", packed),) if packed else (unknown("memory"),)
            value = mk("hash", "keccak256" if base == "sha3" else base, inputs)
        elif base == "abi.encodePacked":
            # Packed, an item takes its static type's width, which a value computed in an inlined callee (a key
            # index, ``add(totalAddedKeys, i)``) no longer says: the argument's declared type does.
            value = mk("enc", base, tuple(_typed_packed(a, v) for a, v in zip(ir.arguments, args)))
        elif base.startswith("abi.encode"):
            value = mk("enc", base, tuple(args))
        elif base.startswith("abi.decode") and args and args[0][0] == "assumed":
            value = args[0]  # decoding what an arranged action returned: arranged too
        elif (
            base.startswith("abi.decode")
            and args
            and args[0][:2] == ("opaque", "returndata")
            and args[0][2][0][0] == "call"
        ):
            # What a view call returned, decoded: its words, when each decoded value is one.
            types = _decoded_types(ir.lvalue)
            if types is None:
                value = mk("opaque", name, tuple(args))
            else:
                items = [mk("item", args[0][2][0], i) for i in range(len(types))]
                value = items[0] if len(items) == 1 else ("tuple", tuple(items))
        elif base.startswith("abi.decode") and args and args[0][0] == "enc" and args[0][1] == "abi.encode":
            words = _static_words(args[0][2])
            types = _decoded_types(ir.lvalue)
            if words is None or types is None:
                value = mk("opaque", name, tuple(args))
            elif len(types) > len(words):
                return State(FALSE, st.env, st.store, st.ret)  # fewer words than it decodes: abi.decode reverts
            else:
                # The word as encoded, when decoded as its own type; decoded as another, strict decoding reverts out of
                # that type's range, which isn't followed.
                decoded = [
                    w if _decodes_as(_type_of(w), str(t)) else unknown(f"unsupported:abi.decode:{_type_of(w)}->{t}")
                    for t, w in zip(types, words)
                ]
                value = decoded[0] if len(decoded) == 1 else ("tuple", tuple(decoded))
        elif base == "ecrecover":
            value = mk("signer", *args)
        elif base == "sload":
            value = read_store(st.store, ("raw", self.this, args[0]))
        elif base == "sstore":
            return State(st.pc, st.env, stored(st.store, ("raw", self.this, args[0]), args[1]), st.ret)
        elif base == "tstore" and len(args) == 2:
            store = stored(st.store, ("transient", self.this, args[0]), args[1])
            return State(st.pc, st.env, store, st.ret, mem=st.mem)
        elif base == "tload" and len(args) == 1:
            # Transient storage is empty when a transaction starts (a reentrancy lock reads zero), save what this call
            # stored there itself.
            value = read_store(st.store, ("transient", self.this, args[0]))
        elif base == "calldataload":
            offset = _small_const(args[0])
            value = (self._calldata_word(offset) if offset is not None else None) or mk("elem", CALLDATA, args[0])
        elif base == "calldatasize":
            value = mk("calldatasize", self._calldata_min)
        elif base in ("code", "extcodesize"):
            value = mk("code", args[0]) if base == "code" else mk("codesize", args[0])
        elif base in ("balance", "selfbalance"):
            value = mk("balance", args[0] if args else self.this)
        elif base == "extcodehash":
            value = mk("codehash", args[0])
        elif base == "returndatasize" and self._last_call is not None:
            value = mk("retsize", self._last_call)
        elif base == "returndatasize":
            value = mk("opaque", "unsupported:returndatasize()", ())  # no call this lowering placed before it
        else:
            value = mk("opaque", name, tuple(args))  # a builtin the lowering doesn't model, still a function of these
        if ir.lvalue is not None:
            return self._write(ir.lvalue, value, st)
        return st

    def _scratch_action(self, mem: tuple, args: list) -> Term | None:
        """``call(gas, token, 0, in, 4 + 32n, ...)`` of a selector and words ``mstore``d at constant offsets
        (OpenZeppelin 5's ``SafeERC20._safeTransferFrom``): the action they name, its function found by selector
        among the compilation's declarations."""
        start, size = _small_const(args[3]), _small_const(args[4])
        if _small_const(args[2]) != 0 or start is None or size is None or size < 4 or (size - 4) % 32:
            return None
        head = next((w for o, w in reversed(mem) if o == start), None)
        value = head[1] if head is not None and head[0] == "const" else None
        if isinstance(value, str):
            try:
                value = int(value, 0)  # a ``bytes4`` constant as Slither writes it (``IERC20.transferFrom.selector``)
            except ValueError:
                return None
        if not isinstance(value, int) or isinstance(value, bool):
            return None
        selector = value if str(head[2]) == "bytes4" or value < 2**32 else value >> 224
        words = [_memory_word(mem, start + 4 + 32 * i) for i in range((size - 4) // 32)]
        if any(w is None for w in words):
            return None
        signature = _signature_of(self.contract, selector, len(words))
        if signature is None:
            return None
        return self._from_here(mk("call", args[1], signature, tuple(_unmasked(w) for w in words), False))

    def _encoded_call(self, target: Term, data: Term, view: bool) -> Term | None:
        """The call ``abi.encodeWithSignature`` / ``abi.encodeWithSelector`` data names, made to ``target``."""
        if not (isinstance(data, tuple) and data and data[0] == "enc" and data[2]):
            return None
        head, rest = data[2][0], tuple(data[2][1:])
        if data[1] == "abi.encodeWithSignature" and head[0] == "const" and isinstance(head[1], str) and "(" in head[1]:
            return self._from_here(mk("call", target, head[1], rest, view))
        if data[1] == "abi.encodeWithSelector" and head[0] == "const":
            value = int(head[1], 0) if isinstance(head[1], str) and head[1][:2] in ("0x", "0X") else head[1]
            if isinstance(head[1], str) and head[1].isdigit():
                value = int(head[1])
            if not isinstance(value, int) or isinstance(value, bool):
                return None
            signature = _signature_of(self.contract, value % 2**32, len(rest))
            return None if signature is None else self._from_here(mk("call", target, signature, rest, view))
        return None

    def _static_call(self, ir: SolidityCall, args: list, st: State) -> State:
        """Assembly ``staticcall(gas, to, add(data, 0x20), mload(data), out, size)`` of data an ``abi.encode*`` built:
        the view call it makes, succeeding when the call returns, its return words left at ``out``. OpenZeppelin's
        ``AuthorityUtils.canCallWithDelay`` asks the access manager this way."""
        call = None
        data = args[2]
        if data[0] == "op" and data[1] == "add":
            encoded = [a for a in data[2] if a[0] == "enc"]
            if len(encoded) == 1 and any(a[0] == "const" and a[1] == 32 for a in data[2]):
                call = self._from_here(_view_call(args[1], encoded[0]))
        out, size = _small_const(args[4]), _small_const(args[5])
        if call is None or out is None or size is None or size % 32:
            cleared = State(st.pc, st.env, st.store, st.ret)  # whatever it returned is somewhere in memory
            value = mk("opaque", ir.function.name, tuple(args))
            return self._write(ir.lvalue, value, cleared) if ir.lvalue is not None else cleared
        written = {out + 32 * i: mk("item", call, i) for i in range(size // 32)}
        mem = (*((o, w) for o, w in st.mem if not out - 31 <= o < out + size), *written.items())
        after = State(st.pc, st.env, st.store, st.ret, mem=mem)
        return self._write(ir.lvalue, mk("ok", call, 0), after) if ir.lvalue is not None else after

    def _external_call(self, ir: HighLevelCall, st: State) -> State:
        target = self.val(ir.destination, st)
        fn = ir.function
        signature = getattr(fn, "solidity_signature", None) or f"{ir.function_name}()"
        view = bool(getattr(fn, "view", False) or getattr(fn, "pure", False) or not isinstance(fn, Function))
        args = tuple(self.val(a, st) for a in ir.arguments)
        value = self._from_here(mk("call", target, signature, args, view))
        returns = getattr(fn, "returns", None) or []
        self._last_call = value
        self._last_returns = len(returns) if isinstance(fn, Function) else None
        if not view:
            st = _acted(st, value)
            if target == self.this:
                # One of this contract's own entry points, run again: what it writes here isn't followed.
                st = replace(
                    st, store=stored(st.store, ("havoc", self.this, "*elsewhere", f"selfcall:{signature}"), TRUE)
                )
        if ir.lvalue is None:
            # A call whose result goes unused still has to return: a view call is there for whether it reverts
            # (``registry.onlyAdmin(sender)``), and so may an action be (``supplyControl.canMintToAddress(to, v,
            # msg.sender)``), which the decision assumes unless it is handed the caller.
            return State(mk_and([st.pc, mk("ok", value, self._last_returns)]), st.env, st.store, st.ret)
        # Any call has to return whether or not its result is read (``token.transferFrom`` returns a bool few check),
        # or read only where the path condition never looks (a view call's value stored, ``total += cap()``): the
        # same revert point as above, on this path.
        st = State(mk_and([st.pc, mk("ok", value, self._last_returns)]), st.env, st.store, st.ret)
        if len(returns) > 1:
            value = ("tuple", tuple(mk("item", value, i) for i in range(len(returns))))
        return self._write(ir.lvalue, value, st)

    def _returned(self, function: Function, index: int, var: Any, st: State) -> Any:
        """A returned value; a ``storage`` return hands back the location itself (a namespaced-storage getter)."""
        returns = function.returns
        held = st.env.get(id(var))
        if index < len(returns) and getattr(returns[index], "is_storage", False):
            if isinstance(held, tuple) and held and held[0] == "loc":
                return held
            loc = self._location(var, st)
            if loc is not None:
                return ("loc", loc)
        return self._value(var, st)  # a value memory holds by reference: the object itself

    def _require_with_error(self, node: Any, st: State) -> Term | None:
        """The condition of ``require(cond, Error())`` when Slither's IR dropped the ``require`` (it keeps only the
        revert); ``None`` when the IR has it, or the node is something else."""
        from slither.core.expressions import CallExpression

        expr = node.expression
        if not isinstance(expr, CallExpression) or not str(expr.called).startswith("require(bool,error)"):
            return None
        if _has_require_with_error(node):
            return None
        return self._expression(expr.arguments[0], st, 0) if expr.arguments else unknown("require_condition")

    def _expression(self, expr: Any, st: State, depth: int) -> Term:
        """A condition from Slither's expression tree, where its IR is missing; anything unhandled is unknown."""
        from slither.core.expressions import (
            BinaryOperation,
            Identifier,
            IndexAccess,
            Literal,
            TupleExpression,
            UnaryOperation,
        )
        from slither.core.expressions import (
            TypeConversion as TypeConv,
        )
        from slither.core.variables.variable import Variable

        if depth > 32:
            return unknown("expression_depth")
        if isinstance(expr, TupleExpression) and len(expr.expressions) == 1:
            return self._expression(expr.expressions[0], st, depth + 1)
        if isinstance(expr, Identifier):
            value = expr.value
            if isinstance(value, (Variable, SolidityVariable)):
                return self.val(value, st)
            return unknown(f"identifier:{expr}")
        if isinstance(expr, Literal):
            folded = _fold_expression(expr, str(expr.type), 0)
            return folded if folded is not None else unknown(f"literal:{expr}")
        if isinstance(expr, TypeConv):
            return _convert(str(expr.type), self._expression(expr.expression, st, depth + 1))
        if isinstance(expr, UnaryOperation):
            inner = self._expression(expr.expression, st, depth + 1)
            op = str(expr.type)
            if op in ("!", "UnaryOperationType.BANG"):
                return mk_not(inner)
            if op in ("~", "UnaryOperationType.TILD"):
                return mk_op("bnot", (inner,))
            return mk("opaque", f"unary:{op}", (inner,))
        if isinstance(expr, BinaryOperation):
            a = self._expression(expr.expression_left, st, depth + 1)
            b = self._expression(expr.expression_right, st, depth + 1)
            op = str(expr.type)
            if op == "&&":
                return mk_and([a, b])
            if op == "||":
                return mk_or([a, b])
            compare = {"==": "eq", "!=": "ne", "<": "lt", ">": "gt", "<=": "le", ">=": "ge"}
            if op in compare:
                return mk_cmp(compare[op], a, b)
            arith = {
                "+": "add",
                "-": "sub",
                "*": "mul",
                "/": "div",
                "%": "mod",
                "**": "pow",
                "<<": "shl",
                ">>": "shr",
                "&": "and",
                "|": "or",
                "^": "xor",
            }
            return mk_op(arith[op], (a, b)) if op in arith else mk("opaque", f"binary:{op}", (a, b))
        if isinstance(expr, IndexAccess):
            base = expr.expression_left
            if isinstance(base, Identifier) and isinstance(base.value, StateVariable) and not base.value.is_constant:
                key = self._expression(expr.expression_right, st, depth + 1)
                return self._read_at((self.this, base.value.name, (("k", key),)), st)
        return unknown(f"expression:{type(expr).__name__}")

    def _legacy_assembly(self, function: Function, asm: str, st: State) -> State:
        """Inline assembly Slither leaves unlowered (Solidity before 0.6): its storage reads and writes and a
        forwarding ``delegatecall`` are read from the text; anything else it assigns becomes unknown."""
        import re

        names: dict[str, Any] = {
            v.name: v for v in [*function.parameters, *function.returns, *function.variables] if v.name
        }
        constants = {
            v.name: v
            for v in [
                *getattr(self.contract.compilation_unit, "variables_top_level", []),
                *self.contract.state_variables,
            ]
            if isinstance(v, TopLevelVariable) or v.is_constant
        }

        def value(token: str) -> Term:
            if token in names:
                return self._value(names[token], st)
            if token in constants:
                return _constant_initializer(constants[token])
            try:
                return const(int(token, 0))
            except ValueError:
                return unknown(f"asm:{token}")

        from .yul import Unsupported, parse

        try:
            return self._yul(parse(asm), names, constants, st)
        except Unsupported:
            pass
        if re.search(r"\b(sstore|delegatecall|callcode)\s*\(", asm):
            # Storage this reading doesn't follow may be written, here or by code run on it: unrecorded. (A call
            # out writes the callee's storage; an event missed only makes a lookup look less logged.)
            self.lost = True
        acts = re.findall(r"\b(call|callcode|delegatecall|create|create2|selfdestruct)\s*\(", asm)
        for act in sorted(set(acts)):
            st = _acted(st, mk("assumed", act))
        if re.search(r"\bsload\s*\(", asm):
            self.raw_reads = True
        assigned = set(re.findall(r"(\w+)\s*:=", asm)) | set(re.findall(r"let\s+(\w+)", asm))
        for name in assigned:
            if name in names:
                st = self._bind(names[name], unknown(f"asm:{name}"), st)
        # What runs before any control flow runs unconditionally; past it, an assignment or a write may not happen.
        flow = re.search(r"\b(if|switch|for|case|default|function|leave|break|continue)\b", asm)
        straight = asm[: flow.start()] if flow else asm
        for target, source in re.findall(r"(\w+)\s*:=\s*(\w+)\s*(?=$|\n|\}|let\b|\w+\s*:=|mstore|sstore)", straight):
            # A plain copy (``output := _input``): the value itself, unless the target is assigned again elsewhere.
            if target in names and len(re.findall(rf"\b{target}\s*:=", asm)) == 1:
                st = self._bind(names[target], value(source), st)
        for target, slot in re.findall(r"(\w+)\s*:=\s*sload\(\s*(\w+)\s*\)", straight):
            if target in names and len(re.findall(rf"\b{target}\s*:=", asm)) == 1:
                st = self._bind(names[target], mk("rawload", self.this, value(slot)), st)
        for target, account in re.findall(r"(\w+)\s*:=\s*extcodesize\(\s*(\w+)\s*\)", straight):
            if target in names and len(re.findall(rf"\b{target}\s*:=", asm)) == 1:
                st = self._bind(names[target], mk("codesize", value(account)), st)
        if len(re.findall(r"\bsstore\(", asm)) > len(re.findall(r"sstore\(\s*(\w+)\s*,\s*(\w+)\s*\)", straight)):
            self.lost = True  # a store this reading doesn't place, or one that may not run
        for slot, written in re.findall(r"sstore\(\s*(\w+)\s*,\s*(\w+)\s*\)", straight):
            st = State(st.pc, st.env, stored(st.store, ("raw", self.this, value(slot)), value(written)), st.ret)
        for found in re.finditer(r"\blog([1-4])\s*\(", straight):
            parts = _call_arguments(straight, found.end())
            if parts is not None:
                topics = tuple(self._asm_topic(part, value) for part in parts[2:])
                st = State(st.pc, st.env, {**st.store, ("emit", f"log{found.group(1)}", topics): TRUE}, st.ret)
        forward = re.search(r"delegatecall\(\s*[^,]+,\s*(\w+)", asm)
        if forward and re.search(r"\breturn\(", asm):
            # A proxy forwarding the call: it returns exactly when the delegate does.
            ok = mk("delegate", value(forward.group(1)))
            return State(mk_and([st.pc, ok]), st.env, st.store, st.ret or (unknown("forwarded"),), halted=True)
        if re.search(r"\b(revert|invalid)\(", asm) and not re.search(r"\b(if|switch|case)\b", asm):
            return State(FALSE, st.env, st.store, st.ret)
        return st

    def _yul(self, statements: list, names: dict, constants: dict, st: State) -> State:
        """Straight-line Yul (``yul.parse``), each builtin as the term the same operation lowers to in Solidity:
        storage reads and writes, events, memory reads as opaque values, and assignments to the function's own
        variables. Raises ``Unsupported`` for anything else that does more than compute a value."""
        from .yul import Assign, Name, Number, Unsupported

        local: dict[str, Term] = {}
        binary = {
            "add": "add",
            "sub": "sub",
            "mul": "mul",
            "div": "div",
            "mod": "mod",
            "exp": "pow",
            "and": "and",
            "or": "or",
            "xor": "xor",
        }
        compare = {"lt": "lt", "gt": "gt", "eq": "eq", "slt": "lt", "sgt": "gt"}

        def ev(e: Any) -> Term:
            if isinstance(e, Number):
                return const(e.value)
            if isinstance(e, Name):
                if e.name in local:
                    return local[e.name]
                if e.name in names:
                    return self.val(names[e.name], st)
                if e.name in constants:
                    return _constant_initializer(constants[e.name])
                raise Unsupported(f"name {e.name}")  # a storage pointer's ``_slot``, a variable unknown here
            args = [ev(a) for a in e.args]
            name = e.name
            if name in binary and len(args) == 2:
                return mk_op(binary[name], tuple(args))
            if name in ("shl", "shr") and len(args) == 2:
                return mk_op(name, (args[1], args[0]))  # Yul shifts by its first argument
            if name in compare and len(args) == 2:
                if name in ("slt", "sgt"):
                    args = [_convert("int256", a) for a in args]  # the words read as signed
                return mk_cmp(compare[name], args[0], args[1])
            if name in ("sdiv", "smod", "sar") and len(args) == 2:
                if name == "sar":
                    return _convert("int256", mk_op("sar", (_convert("int256", args[1]), args[0])))
                x, y = (_convert("int256", a) for a in args)
                return _convert("int256", mk_op(name, (x, y)))
            if name in ("byte", "signextend") and len(args) == 2:
                return mk_op(name, tuple(args))
            if name == "calldatasize" and not args:
                return mk("calldatasize", self._calldata_min)
            if name == "chainid" and not args:
                return mk("time", "chainid")
            if name in ("selfbalance", "balance") and len(args) == (0 if name == "selfbalance" else 1):
                return mk("balance", args[0] if args else self.this)
            if name == "iszero" and len(args) == 1:
                inner = args[0]
                return mk_not(inner) if inner[0] in ("cmp", "not", "and", "or") else mk_cmp("eq", inner, const(0))
            if name == "not" and len(args) == 1:
                return mk_op("bnot", (args[0],))
            if name == "sload" and len(args) == 1:
                return mk("rawload", self.this, args[0])
            if name == "caller" and not args:
                return self.sender
            if name == "address" and not args:
                return self.this
            if name == "callvalue" and not args:
                return mk("callvalue")
            if name == "timestamp" and not args:
                return mk("time", "timestamp")
            if name == "number" and not args:
                return mk("time", "number")
            if name == "extcodesize" and len(args) == 1:
                return mk("codesize", args[0])
            if name == "calldataload" and len(args) == 1:
                offset = _small_const(args[0])
                word = self._calldata_word(offset) if offset is not None else None
                return word if word is not None else mk("elem", CALLDATA, args[0])
            if name in ("mload", "keccak256", "addmod", "mulmod", "gas", "returndatasize", "msize"):
                # Memory this reading doesn't track, what the gas or the last call leave: unknown by name (``addmod``
                # and ``mulmod`` are evaluated exactly from it).
                if name == "mload":
                    return _lost_word("mload(uint256)", args)
                return mk("opaque", name, tuple(args))
            raise Unsupported(f"builtin {name}")

        for statement in statements:
            if isinstance(statement, Assign):
                if len(statement.targets) != 1:
                    raise Unsupported("several targets")
                target = statement.targets[0]
                if (
                    isinstance(statement.value, Name)
                    and statement.value.name in names
                    and statement.value.name not in local
                ):
                    term = self._value(names[statement.value.name], st)  # a plain copy: the same object, if one
                else:
                    term = const(0) if statement.value is None else ev(statement.value)
                if target in local or target not in names:
                    local[target] = term
                else:
                    st = self._bind(names[target], term, st)
                continue
            call = statement.call
            if call.name == "sstore" and len(call.args) == 2:
                slot, written = ev(call.args[0]), ev(call.args[1])
                st = State(st.pc, st.env, stored(st.store, ("raw", self.this, slot), written), st.ret)
            elif call.name in ("mstore", "mstore8", "calldatacopy", "codecopy", "returndatacopy"):
                for a in call.args:
                    ev(a)
                st = replace(st, mem=())  # memory this reading doesn't track
            elif call.name == "pop":
                ev(call.args[0])
            elif call.name in ("log1", "log2", "log3", "log4"):
                topics = [ev(a) for a in call.args[2:]]
                topics = [mk("sig") if _selector_word(t) else t for t in topics]
                st = State(st.pc, st.env, {**st.store, ("emit", call.name, tuple(topics)): TRUE}, st.ret)
            elif call.name in ("revert", "invalid"):
                return State(FALSE, st.env, st.store, st.ret)
            else:
                raise Unsupported(f"statement {call.name}")
        return st

    def _asm_topic(self, text: str, value: Callable[[str], Term]) -> Term:
        """A legacy-assembly log topic: the selector (DSS ``note``'s ``shl(224, shr(224, calldataload(0)))``), an
        argument read from calldata, the caller, or a named value."""
        text = re.sub(r"\s+", "", text)
        if text in (
            "shl(224,shr(224,calldataload(0)))",
            "and(calldataload(0),not(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff))",
        ):
            return mk("sig")
        loaded = re.fullmatch(r"calldataload\((\w+)\)", text)
        if loaded:
            try:
                return self._calldata_word(int(loaded.group(1), 0)) or unknown("asm:calldata")
            except ValueError:
                return unknown("asm:calldata")
        if text in ("caller", "caller()"):
            return self.sender
        if re.fullmatch(r"\w+", text):
            return value(text)
        return unknown("asm:topic")

    def _calldata_word(self, offset: int) -> Term | None:
        """``calldataload(4 + 32 i)``: the call's ``i``-th argument, when it and every one before it is one word."""
        if offset < 4 or (offset - 4) % 32:
            return None
        index = (offset - 4) // 32
        if index >= len(self._arguments):
            return None
        for a in self._arguments[: index + 1]:
            type_ = a[2] if a[0] == "arg" else None
            if not isinstance(type_, str) or not _one_word(type_):
                return None
        return self._arguments[index]

    def _yul_sload_of_constant(self, value: Any) -> bool:
        if not (isinstance(value, StateVariable) and value.is_constant) or self._node is None:
            return False
        source = _source(self._node, lambda text: f"sload({value.name})" in text.replace(" ", ""))
        return bool(source)

    # Storage ----------------------------------------------------------------------------------------------------------
    # A location is (contract, variable, path); a reference variable holds ``("loc", location)``.

    def _index(self, ir: Index, st: State) -> State:
        """``a[k]``: a storage location one step further, or an item of a value held in memory or calldata (read and
        written through an ``mref``). Either reverts out of range (Panic 0x32) for an array: the bound is part of
        the path. ``bytes`` index to a byte, not to a word."""
        left = ir.variable_left
        type_ = getattr(left, "type", None)
        base = self._location(left, st)
        key = self.val(ir.variable_right, st)
        if base is None and self._unplaced_pointer(left, st):
            return self._unplaced(ir.lvalue, st)
        if base is not None:
            if _bytes_typed(type_):
                # A byte of a ``bytes``/``string`` in storage: its encoding (length in the slot, long data hashed)
                # isn't a path this lowering places.
                st = replace(st, pc=mk_and([st.pc, unknown("unsupported:storage_bytes_index")]))
            else:
                bound = self._storage_bound(type_, base, key, st)
                if bound is not None:
                    st = replace(st, pc=mk_and([st.pc, bound]))
            return self._bind(ir.lvalue, ("loc", _extend(base, ("k", key))), st)
        container = self.val(left, st)
        kind = "byte" if _bytes_typed(type_) or container == CALLDATA else "elem"
        length = _fixed_length(type_)
        size = const(length) if length is not None else self._length(container, type_)
        st = replace(st, pc=mk_and([st.pc, mk_cmp("lt", key, size)]))
        self._vars[id(left)] = left
        return self._bind(ir.lvalue, ("mref", id(left), key, kind), st)

    def _length(self, container: Term, type_: Any = None) -> Term:
        if container == CALLDATA:
            return mk("calldatasize", self._calldata_min)
        if _bytes_typed(type_) and container[0] == "load":
            return mk("len", container)  # a ``bytes``/``string`` copied from storage: its length is in its encoding
        found = length_of(container)
        return found if found is not None else mk("len", container)

    def _storage_bound(self, type_: Any, base: tuple, key: Term, st: State) -> Term | None:
        """``key`` within a storage array at ``base``: below its length slot (dynamic) or its declared length."""
        from slither.core.solidity_types import ArrayType

        if not isinstance(type_, ArrayType):
            return None  # a mapping: every key is there
        fixed = _fixed_length(type_)
        if fixed is not None:
            return mk_cmp("lt", key, const(fixed))
        size = self._read_at(_extend(base, ("f", "length")), st)
        if (
            size[:2] == ("op", "add")
            and key in size[2]
            and key[0] == "load"
            and key[3][-1:] == (("f", "length"),)
            and any(_small_const(x) is not None and x != key for x in size[2])
        ):
            return None  # ``push``: the old length below the new one (a storage array's length stays below 2**64)
        return mk_cmp("lt", key, size)

    def _member(self, ir: Member, st: State) -> State:
        field_name = str(getattr(ir.variable_right, "value", ir.variable_right))
        base = self._location(ir.variable_left, st)
        if base is None and self._unplaced_pointer(ir.variable_left, st):
            return self._unplaced(ir.lvalue, st)
        if base is not None:
            return self._bind(ir.lvalue, ("loc", _extend(base, ("f", field_name))), st)
        enum = _enum_of(ir.variable_left)
        if enum is not None:
            index = _enum_index(self.contract, enum, field_name)
            value = const(index, "uint8") if index is not None else unknown("enum")
            return self._write(ir.lvalue, value, st)  # ``Operation.Call``
        if isinstance(ir.variable_left, Contract):
            # ``PercentageMath.PERCENTAGE_FACTOR``: a library's or contract's constant, by its initializer.
            declared = next(
                (v for v in ir.variable_left.state_variables if v.name == field_name and v.is_constant), None
            )
            if declared is not None:
                return self._write(ir.lvalue, _constant_initializer(declared), st)
            # ``IAuthority.canCall`` as a value (``abi.encodeCall``'s first argument): the function it names.
            named = {f.solidity_signature for f in ir.variable_left.functions if f.name == field_name}
            if len(named) == 1:
                return self._write(ir.lvalue, const(named.pop(), "function"), st)
        whole = self.val(ir.variable_left, st)
        word = _static_field(getattr(ir.variable_left, "type", None), field_name)
        if word is not None and isinstance(whole, tuple) and whole and whole[0] == "call":
            # A field of a struct a call returns: a struct of plain values is encoded as their words, in order.
            return self._write(ir.lvalue, mk("item", whole, word), st)
        if _struct_shaped(whole, field_name):
            if ir.lvalue is not None:
                # A field of a memory struct: read from, and written back into, the struct this call holds.
                self._structs[id(ir.variable_left)] = ir.variable_left
                return self._bind(ir.lvalue, ("sref", id(ir.variable_left), field_name), st)
            return self._write(ir.lvalue, _field_of(whole, field_name), st)
        if isinstance(whole, tuple) and whole and whole[0] == "load":
            # A field of a struct read whole from storage (``Config memory c = _config; c.epoch``): that field's slot.
            return self._write(ir.lvalue, mk("load", whole[1], whole[2], (*whole[3], ("f", field_name))), st)
        if isinstance(whole, tuple) and whole and whole[0] == "arg" and ir.lvalue is not None:
            # A field of a struct the caller passes is a value the caller picks, like any argument.
            return self._write(ir.lvalue, _typed_arg(f"{whole[1]}.{field_name}", ir.lvalue.type), st)
        if (
            isinstance(whole, tuple)
            and whole[:1] == ("elem",)
            and whole[1][0] == "arg"
            and ir.lvalue is not None
            and not _reference_typed(getattr(ir.lvalue, "type", None))
        ):
            # A field of an item of an array of structs the caller passes: the caller picks it for each item.
            column = mk("arg", f"{whole[1][1]}[].{field_name}", f"{ir.lvalue.type}[]")
            return self._write(ir.lvalue, mk("elem", column, whole[2]), st)
        if field_name in ("codesize", "codehash") and _address_typed(getattr(ir.variable_left, "type", None)):
            return self._write(ir.lvalue, mk(field_name, whole), st)  # ``address(token).code.length``
        # A field of any other value (one another contract returned, encoded with dynamic parts): unknown by name.
        return self._write(ir.lvalue, mk("opaque", f"unsupported:member:{field_name}", (whole,)), st)

    def _unplaced_pointer(self, var: Any, st: State) -> bool:
        """A storage pointer (a local, or a reference into one) with no one location: a choice by branch."""
        if isinstance(var, StateVariable) or not getattr(var, "is_storage", False):
            return False
        held = st.env.get(id(var))
        return isinstance(held, tuple) and held[:2] == ("unknown", "unsupported:storage_pointer_choice")

    def _unplaced(self, lvalue: Any, st: State) -> State:
        """A part of storage through such a pointer: read unknown, and any write through it may land anywhere in
        this contract's storage, which reads unknown from here."""
        self.lost = True
        label = "unsupported:storage_pointer_choice"
        st = State(st.pc, st.env, stored(st.store, ("havoc", self.this, "*", label), TRUE), st.ret, mem=st.mem)
        env = dict(st.env)
        env[id(lvalue)] = unknown(label)
        return State(st.pc, env, st.store, st.ret, mem=st.mem)

    def _location(self, var: Any, st: State) -> tuple | None:
        if isinstance(var, StateVariable) and not (var.is_constant or var.is_immutable):
            return (self.this, var.name, ())
        held = st.env.get(id(var))
        if isinstance(held, tuple) and held and held[0] == "loc":
            return held[1]
        return None

    def _read_at(self, loc: tuple, st: State) -> Term:
        """Storage at ``loc`` as this call sees it (``read_store``)."""
        return read_store(st.store, loc)

    def _bind(self, lvalue: Any, value: Any, st: State) -> State:
        if self._memory_var(lvalue) and not _pointer(value) and not _reference(value):
            return self._allocate(lvalue, value, st)  # a new value in memory: an object of its own
        env = dict(st.env)
        env[id(lvalue)] = value
        return State(st.pc, env, st.store, st.ret, mem=st.mem)

    def _write(self, lvalue: Any, value: Any, st: State) -> State:
        ref = st.env.get(id(lvalue))
        if isinstance(ref, tuple) and ref and ref[0] == "mref":
            # An item written in place: in the object holding it, or in the value holding it, written back where that
            # value lives (an item or field of another value: ``g[1][0] = x``, ``s.xs[i] = x``).
            key, byte = ref[2], ref[3] == "byte"
            return self._mutate(
                self._vars[ref[1]],
                lambda c: mk("upd", c, (("k", key),), value) if byte else update(c, key, value),
                st,
            )
        if isinstance(ref, tuple) and ref and ref[0] == "sref":
            name = ref[2]

            def field(c: Term) -> Term:
                if isinstance(c, tuple) and c and c[0] == "struct" and name in c[1]:
                    at = c[1].index(name)
                    return mk("struct", c[1], (*c[2][:at], value, *c[2][at + 1 :]))
                return unknown("memory")

            return self._mutate(self._structs[ref[1]], field, st)
        loc = self._location(lvalue, st)
        if loc is not None:
            # Storage holds a copy: whatever objects the value points to, read out.
            return State(st.pc, st.env, stored(st.store, loc, self._deep(value, st)), st.ret, mem=st.mem)
        if getattr(lvalue, "is_storage", False) and not isinstance(lvalue, (StateVariable, ReferenceVariable)):
            # Written through a storage pointer whose location isn't one place: any of this contract's storage.
            self.lost = True
            return State(
                st.pc, st.env, stored(st.store, ("havoc", self.this, "*", "unsupported:pointer"), TRUE), st.ret
            )
        return self._bind(lvalue, value, st)

    # Memory -----------------------------------------------------------------------------------------------------------
    # A value memory holds by reference (an array, ``bytes``, a struct) is an object in the store, ``("heap", n)``; a
    # variable holds ``("ptr", n)``. Every name for one object (``b = a``, a parameter, a struct field holding it) sees
    # every write into it; reassigning a name points it elsewhere. ``val`` reads values with every object read out.

    def _memory_var(self, var: Any) -> bool:
        """A local, parameter or temporary holding a value memory keeps by reference."""
        if isinstance(var, (StateVariable, ReferenceVariable, Constant, SolidityVariable)):
            return False
        if getattr(var, "is_storage", False) or getattr(var, "location", None) in ("storage", "calldata"):
            return False
        return _reference_typed(getattr(var, "type", None))

    def _allocate(self, var: Any, value: Any, st: State) -> State:
        self._objects += 1
        env = dict(st.env)
        env[id(var)] = mk("ptr", self._objects)
        return State(st.pc, env, stored(st.store, ("heap", self._objects), value), st.ret, mem=st.mem)

    def _object(self, value: Any, st: State) -> Any:
        """What a pointer points to (each pointer of a choice between them); anything else as it is."""
        if isinstance(value, tuple) and value and value[0] == "ptr":
            return st.store.get(("heap", value[1]), unknown("unallocated"))
        if isinstance(value, tuple) and value and value[0] == "ite" and _pointer(value):
            return mk_ite(value[1], self._object(value[2], st), self._object(value[3], st))
        return value

    def _mutate(self, holder: Any, change: Callable[[Term], Term], st: State) -> State:
        """``holder``'s value changed in place: the objects it points to, else the value written back to ``holder``."""
        current = self._value(holder, st)
        if not _pointer(current):
            return self._write(holder, change(current), st)
        conditions: dict[int, list] = {}

        def leaves(t: Any, cond: Term) -> None:
            if t[0] == "ptr":
                conditions.setdefault(t[1], []).append(cond)
            elif t[0] == "ite":
                leaves(t[2], mk_and([cond, t[1]]))
                leaves(t[3], mk_and([cond, mk_not(t[1])]))

        leaves(current, TRUE)
        store = st.store
        for oid, conds in sorted(conditions.items()):
            old = store.get(("heap", oid), unknown("unallocated"))
            store = stored(store, ("heap", oid), mk_ite(mk_or(conds), change(old), old))
        return State(st.pc, st.env, store, st.ret, mem=st.mem)

    def _deep(self, value: Any, st: State, depth: int = 0) -> Any:
        """``value`` with every object it points to read out, to a bounded depth."""
        if not self._objects or not isinstance(value, tuple) or not contains(value, frozenset({"ptr"})):
            return value
        if depth > 8:
            return unknown("memory_depth")

        def out(p: Term) -> Term:
            return self._deep(st.store.get(("heap", p[1]), unknown("unallocated")), st, depth + 1)

        if isinstance(value, Term):
            # The same value over the same objects reads out the same: remembered, since a value holding pointers is
            # read again and again while the objects stay as they are.
            pointed: list = []
            seen: set = set()
            pending = list(_pointers(value))
            while pending:  # every object it reaches, through objects holding pointers too
                p = pending.pop()
                if p[1] in seen:
                    continue
                seen.add(p[1])
                held = st.store.get(("heap", p[1]))
                pointed.append((p[1], held))
                if isinstance(held, Term):
                    pending.extend(_pointers(held))
            key = (value, tuple(sorted(pointed, key=lambda x: x[0])), depth)
            memo = self.__dict__.setdefault("_deep_memo", {})
            if key not in memo:
                if len(memo) > 50_000:
                    memo.clear()
                memo[key] = substitute(value, "ptr", out)
            return memo[key]
        return tuple(self._deep(x, st, depth) if isinstance(x, tuple) else x for x in value)

    # Values -----------------------------------------------------------------------------------------------------------

    def _arguments_only(self) -> bool:
        """Whether every ``msg.data`` in this statement is ``msg.data[4:]``, the arguments without the selector,
        which Slither's IR renders as ``msg.data`` itself; read from the source."""
        source = _source(self._node, lambda text: "msg.data" in text)
        uses = source.count("msg.data")
        return uses > 0 and len(_ARGUMENTS_SLICE.findall(source)) == uses

    def val(self, var: Any, st: State) -> Any:
        """``var``'s value, every object it points to read out."""
        return self._deep(self._value(var, st), st)

    def _value(self, var: Any, st: State) -> Any:
        """``var``'s value as it is held: a value memory keeps by reference is its pointer."""
        if isinstance(var, Constant):
            return _constant(var)
        if isinstance(var, (SolidityVariableComposed, SolidityVariable)):
            if var.name == "msg.sender":
                return self.sender
            if var.name == "this":
                return self.this
            if var.name == "msg.data" and self._arguments_only():
                return mk("enc", "abi.encode", self._arguments)
            if var.name == "msg.data" and self._sliced:
                return unknown("unsupported:slice")  # Slither drops ``x[a:b]``: what is read isn't the whole
            if var.name == "msg.value" and not self._payable:
                return const(0)  # a call to a function that isn't payable carrying ether reverts
            if var.name in _ENVIRONMENT:
                return _ENVIRONMENT[var.name]
            label = REJECTED_VARIABLES.get(var.name, f"unsupported:{var.name}")
            # A value of the environment nobody's identity is in (Vyper's ``self`` aside): unknown by name.
            return mk("opaque", label, ()) if var.name in REJECTED_VARIABLES and "." in var.name else unknown(label)
        if isinstance(var, Contract):
            return unknown(f"contract:{var.name}")
        if isinstance(var, TopLevelVariable):
            return _constant_initializer(var)  # a file-level ``constant`` (the only kind there is)
        if isinstance(var, StateVariable):
            if var.is_constant:
                return _constant_initializer(var)
            if var.is_immutable:
                return mk("immutable", self.code, var.name)
            return self._read_at((self.this, var.name, ()), st)
        held = st.env.get(id(var))
        if isinstance(held, tuple) and held and held[0] == "loc":
            return self._read_at(held[1], st)
        if isinstance(held, tuple) and held and held[0] == "mref":
            holder = self._vars[held[1]]
            container = self._object(self._value(holder, st), st)
            if held[3] == "byte":
                return byte_at(self._deep(container, st), held[2])
            return element(container, held[2], _zero_item(getattr(holder, "type", None)))
        if isinstance(held, tuple) and held and held[0] == "sref":
            whole = self._object(self._value(self._structs[held[1]], st), st)
            return _field_of(whole, held[2])
        if self._sliced and isinstance(held, tuple) and held[:1] == ("arg",) and _dynamic_abi(held[2]):
            return unknown("unsupported:slice")  # Slither drops ``x[a:b]``: what is read isn't the whole
        if held is not None:
            return held
        if isinstance(var, ReferenceVariable):
            return unknown("reference")
        return _zero(getattr(var, "type", None))


def _schedule(start: Any) -> tuple[list[Any], dict[int, list[tuple[Any, str]]]]:
    """Nodes reachable from ``start`` in topological order of forward edges, and each node's out-edges tagged
    ``forward`` or ``back`` (to a node still on the depth-first stack)."""
    edges: dict[int, list[tuple[Any, str]]] = {}
    nodes: dict[int, Any] = {}
    on_stack: set[int] = set()
    stack = [(start, iter(start.sons))]
    nodes[id(start)] = start
    on_stack.add(id(start))
    edges[id(start)] = []
    while stack:
        node, sons = stack[-1]
        son = next(sons, None)
        if son is None:
            stack.pop()
            on_stack.discard(id(node))
            continue
        if id(son) in on_stack:
            edges[id(node)].append((son, "back"))
            continue
        edges[id(node)].append((son, "forward"))
        if id(son) not in nodes:
            nodes[id(son)] = son
            edges[id(son)] = []
            on_stack.add(id(son))
            stack.append((son, iter(son.sons)))
    # A back edge to a loop header delivers to the header's exit, so it orders the latch before the exit. One into a
    # ``do`` body comes from the condition node, whose own false son is the exit.
    indegree = dict.fromkeys(nodes, 0)
    successors: dict[int, list[Any]] = {k: [] for k in nodes}
    for key, out in edges.items():
        for son, kind in out:
            target = son if kind == "forward" else son.son_false if son.type == NodeType.IFLOOP else None
            if target is None or id(target) not in nodes:
                continue
            successors[key].append(target)
            indegree[id(target)] += 1
    ready = [n for k, n in nodes.items() if indegree[k] == 0]
    order = []
    while ready:
        node = ready.pop()
        order.append(node)
        for target in successors[id(node)]:
            indegree[id(target)] -= 1
            if indegree[id(target)] == 0:
                ready.append(target)
    if len(order) < len(nodes):
        # An irreducible cycle (not an IFLOOP header): its nodes never run, and the caller sees no exit through them.
        pass
    return order, edges


def _has_require_with_error(node: Any) -> bool:
    return any(isinstance(ir, SolidityCall) and ir.function.name.startswith("require(bool,error)") for ir in node.irs)


MAX_ARRAY_ITEMS = 64


def _new_array(length: Term) -> Term:
    """``new T[](n)``: zeroed items when ``n`` is a small constant, so writes to them can be followed."""
    if length[0] == "const" and isinstance(length[1], int) and 0 <= length[1] <= MAX_ARRAY_ITEMS:
        return mk("array", length, tuple(const(0, "uint256") for _ in range(length[1])))
    return mk("array", length)


def _typed_packed(var: Any, value: Term) -> Term:
    """``value`` as packed by ``var``'s declared type, when its own shape doesn't give the width."""
    type_ = str(getattr(var, "type", ""))
    if packed_width(value) is not None or not re.fullmatch(r"address|bool|u?int\d*|bytes\d+", type_):
        return value
    return mk("conv", type_, value)


def _static_words(values: tuple) -> list[Term] | None:
    """The words ``abi.encode(values)`` lays out, when each value is a one-word value of known type."""
    words = []
    for v in values:
        type_ = v[2] if v[0] in ("arg", "const") and isinstance(v[2], str) else v[1] if v[0] == "conv" else None
        if type_ is None or type_ in ("bytes", "string") or "[" in type_ or "(" in type_:
            return None
        words.append(v)
    return words


def _decodes_as(encoded: str | None, decoded: str) -> bool:
    """Whether a word ``abi.encode`` made of an ``encoded`` value decodes as ``decoded`` to the same number: the same
    type, or an integer type whose range holds the encoded one's (an address read as ``uint256``)."""
    if encoded == decoded:
        return True

    def range_of(type_: str | None) -> tuple[int, bool] | None:
        if type_ in ("address", "address payable"):
            return 160, False
        if type_ == "bool":
            return 1, False
        found = re.fullmatch(r"(u?)int(\d*)", type_ or "")
        return (int(found.group(2) or 256), found.group(1) == "") if found else None

    a, b = range_of(encoded), range_of(decoded)
    if a is None or b is None or (b[0] == 1 and a[0] != 1):
        return False
    return (a[1] == b[1] and a[0] <= b[0]) or (not a[1] and b[1] and a[0] < b[0])


def _type_of(value: Term) -> str | None:
    if value[0] in ("arg", "const") and isinstance(value[2], str):
        return value[2]
    return value[1] if value[0] == "conv" else None


def _decoded_types(lvalue: Any) -> list[Any] | None:
    """The types an ``abi.decode`` produces, when each is a one-word value."""
    type_ = getattr(lvalue, "type", None)  # a tuple variable's is the list of its items' types
    types = list(type_) if isinstance(type_, list) else [type_] if type_ is not None else []
    if not types or any(
        not isinstance(t, ElementaryType) or str(t) in ("bytes", "string") or str(t).endswith("]") for t in types
    ):
        return None
    return types


def _address_typed(type_: Any) -> bool:
    """An address, or a contract (an address the source calls through)."""
    from slither.core.declarations import Contract
    from slither.core.solidity_types import UserDefinedType

    return str(type_) in ("address", "address payable") or (
        isinstance(type_, UserDefinedType) and isinstance(type_.type, Contract)
    )


def _pointers(term: Term) -> frozenset:
    """The pointers anywhere in ``term``, remembered on each node (bottom-up: a value read again and again, and the
    new values built over it, walk only what is new)."""
    from .terms import _children

    local: dict[int, frozenset] = {}
    stack: list[tuple[Any, bool]] = [(term, False)]
    while stack:
        node, expanded = stack.pop()
        if id(node) in local:
            continue
        cached = node.__dict__.get("_ptrs") if isinstance(node, Term) else None
        if cached is not None:
            local[id(node)] = cached
            continue
        if isinstance(node, Term) and not contains(node, frozenset({"ptr"})):
            local[id(node)] = frozenset()
            continue
        children = [c for c in _children(node) if isinstance(c, tuple)]
        if not expanded:
            stack.append((node, True))
            stack.extend((c, False) for c in children if id(c) not in local)
            continue
        found = frozenset().union(*(local[id(c)] for c in children))
        if node and node[0] == "ptr":
            found = found | {node}
        local[id(node)] = found
        if isinstance(node, Term):
            node.__dict__["_ptrs"] = found
    return local[id(term)]


def _pointer(value: Any) -> bool:
    """A pointer to an object in memory, or a choice between pointers (a branch that set none leaves it unknown)."""
    if not isinstance(value, tuple) or not value:
        return False
    if value[0] == "ptr":
        return True
    if value[0] == "ite":
        sides = (value[2], value[3])
        return any(_pointer(x) for x in sides) and all(_pointer(x) or x[0] in ("unknown", "opaque") for x in sides)
    return False


def _reference(value: Any) -> bool:
    """A reference the lowering binds a variable to: a storage location, an item, a field."""
    return isinstance(value, tuple) and bool(value) and value[0] in ("loc", "mref", "sref")


def _struct_shaped(value: Any, name: str) -> bool:
    """A struct value with field ``name``, or a choice between such."""
    if not isinstance(value, tuple) or not value:
        return False
    if value[0] == "ite":
        return _struct_shaped(value[2], name) and _struct_shaped(value[3], name)
    return value[0] == "struct" and name in value[1]


def _field_of(whole: Any, name: str) -> Term:
    """Field ``name`` of a struct value (each side of a choice between them)."""
    if isinstance(whole, tuple) and whole and whole[0] == "struct" and name in whole[1]:
        return whole[2][whole[1].index(name)]
    if isinstance(whole, tuple) and whole and whole[0] == "ite":
        return mk_ite(whole[1], _field_of(whole[2], name), _field_of(whole[3], name))
    return unknown("memory")


def _operand_type(ir: Binary) -> Any:
    """The type an operation computes in: its left operand's (a shift's always), else its right's where the left
    is a literal Slither may have typed loosely."""
    left, right = ir.variable_left, ir.variable_right
    if (
        isinstance(left, Constant)
        and not isinstance(right, Constant)
        and ir.type
        not in (
            BinaryType.LEFT_SHIFT,
            BinaryType.RIGHT_SHIFT,
        )
    ):
        return getattr(right, "type", None)
    return getattr(left, "type", None) or getattr(ir.lvalue, "type", None)


def _integer(type_: Any) -> tuple[int, bool]:
    """(bits, signed) of an integer-like type (a ``bytesN`` its ``8N`` bits, anything else a 256-bit word)."""
    name = str(type_ or "")
    found = re.fullmatch(r"(u?)int(\d*)", name)
    if found:
        return int(found.group(2) or 256), found.group(1) == ""
    found = re.fullmatch(r"bytes(\d+)", name)
    if found:
        return 8 * int(found.group(1)), False
    return 256, False


def _checked_version(contract: Any) -> bool:
    version = str(getattr(contract.compilation_unit, "solc_version", "") or "")
    parts = [int(x) for x in version.split(".")[:2] if x.isdigit()]
    return len(parts) == 2 and parts >= [0, 8]


def _enum_size(type_: Any) -> int | None:
    from slither.core.declarations import Enum
    from slither.core.solidity_types import UserDefinedType

    if isinstance(type_, UserDefinedType) and isinstance(type_.type, Enum):
        return len(type_.type.values)
    return None


_SLICE = re.compile(r"([A-Za-z_$][\w.$]*)\s*\[\s*([^\[\]:]*?)\s*:\s*([^\[\]:]*?)\s*\]")


def _sliced(node: Any) -> tuple[bool, list]:
    """Whether ``node``'s source slices a value (``x[a:b]``, which Slither's IR renders as ``x``) other than as read
    back exactly: ``msg.data[4:]`` (the arguments), and ``bytesN(x[:N])``, the first N bytes, which is ``bytesN(x)``
    once ``x`` holds N bytes (returned as (x, N): the slice reverts otherwise). A conditional expression inside an
    index reads as a slice too: never fewer."""
    # The statement's own expression: a node's source spans what it opens too (an ``if``'s whole body).
    expression = getattr(node, "expression", None)
    text = _source(expression, lambda t: ":" in t) if expression is not None else ""
    cuts = []
    for found in _SLICE.finditer(text):
        base, start, end = found.groups()
        if base == "msg.data" and start in ("4", "0x4", "0x04") and not end:
            continue
        cast = re.search(r"bytes(\d+)\(\s*$", text[: found.start()])
        if cast and start in ("", "0") and end == cast.group(1) and text[found.end() :].lstrip().startswith(")"):
            cuts.append((base, int(end)))
            continue
        return True, []
    return False, cuts


def _dynamic_abi(type_: Any) -> bool:
    return isinstance(type_, str) and (type_ in ("bytes", "string") or type_.endswith("]"))


def _bytes_typed(type_: Any) -> bool:
    return str(type_) in ("bytes", "string")


def _fixed_length(type_: Any) -> int | None:
    """The declared length of a fixed-size array type (``T[3]``)."""
    from slither.core.solidity_types import ArrayType

    if not isinstance(type_, ArrayType) or not type_.is_fixed_array:
        return None
    length = type_.length_value
    text = str(getattr(length, "value", "")) if length is not None else ""
    return int(text) if text.isdigit() else None


def _rank(type_: Any) -> int | None:
    """How many array dimensions a type has (``bytes`` and ``string`` none); ``None`` when the type isn't one."""
    from slither.core.solidity_types import ArrayType, Type

    if not isinstance(type_, Type):
        return None
    rank = 0
    while isinstance(type_, ArrayType):
        type_, rank = type_.type, rank + 1
    return rank


def _zero_item(type_: Any) -> Term | None:
    """What an item of a freshly allocated array of ``type_`` holds."""
    from slither.core.solidity_types import ArrayType

    return _zero(type_.type) if isinstance(type_, ArrayType) else None


def _array_shaped(term: Any) -> bool:
    """A memory array, or a choice between them."""
    if not isinstance(term, tuple) or not term:
        return False
    if term[0] == "ite":
        return _array_shaped(term[2]) and _array_shaped(term[3])
    return term[0] == "array"


def _items(term: Any) -> tuple | None:
    """A memory array's items, when this call made it with a known length."""
    if isinstance(term, tuple) and len(term) == 3 and term[0] == "array":
        return term[2]
    return None


def _static_field(type_: Any, name: str) -> int | None:
    """The word ``name`` occupies in an ABI-encoded struct of ``type_`` whose fields are all of fixed size, when it
    is one word itself."""
    from slither.core.declarations import Structure
    from slither.core.solidity_types import UserDefinedType

    if not (isinstance(type_, UserDefinedType) and isinstance(type_.type, Structure)):
        return None
    word = 0
    for f in type_.type.elems_ordered:
        size = _type_words(f.type)
        if size is None:
            return None
        if f.name == name:
            return word if size == 1 else None
        word += size
    return None


def _type_words(type_: Any) -> int | None:
    """The words a value of ``type_`` takes encoded in place, ``None`` for one encoded elsewhere (``bytes``, a
    dynamic array, a struct holding one)."""
    from slither.core.declarations import Contract, Enum, Structure
    from slither.core.solidity_types import ArrayType, UserDefinedType
    from slither.core.solidity_types.type_alias import TypeAlias

    if isinstance(type_, ElementaryType):
        return None if str(type_) in ("bytes", "string") else 1
    if isinstance(type_, TypeAlias):
        return 1  # ``type Duration is uint32``
    if isinstance(type_, UserDefinedType):
        if isinstance(type_.type, (Enum, Contract)):
            return 1
        if isinstance(type_.type, Structure):
            sizes = [_type_words(f.type) for f in type_.type.elems_ordered]
            return None if any(s is None for s in sizes) else sum(sizes)
    if isinstance(type_, ArrayType) and type_.is_fixed_array:
        inner = _type_words(type_.type)
        length = _small_const(const(int(str(type_.length)), "uint256")) if str(type_.length).isdigit() else None
        return None if inner is None or length is None else inner * length
    return None


def _enum_index(contract: Any, enum: Any, member: str) -> int | None:
    """``member``'s value in ``enum``. Two files each declaring a top-level ``enum State`` both resolve to whichever
    Slither saw first, so the value counts only when every enum of that name holding ``member`` agrees on it."""
    unit = contract.compilation_unit
    pool = [enum, *getattr(unit, "enums_top_level", []), *(e for c in unit.contracts for e in c.enums)]
    found = {e.values.index(member) for e in pool if e.name == enum.name and member in e.values}
    return found.pop() if len(found) == 1 else None


def _item(whole: Any, index: int) -> Term:
    """Value ``index`` of several: of a tuple, of each branch's tuple where they were merged, else of the call."""
    if isinstance(whole, tuple) and whole and whole[0] == "tuple":
        return whole[1][index] if index < len(whole[1]) else unknown("tuple_index")
    if isinstance(whole, tuple) and whole and whole[0] == "ite":
        return mk_ite(whole[1], _item(whole[2], index), _item(whole[3], index))
    return mk("item", whole, index)


def _signature_of(contract: Any, selector: int, arity: int) -> str | None:
    """The one signature of ``arity`` parameters with ``selector`` declared anywhere in ``contract``'s compilation."""
    cache = contract.compilation_unit.__dict__.setdefault("_psat_selectors", {})
    if not cache:
        for c in contract.compilation_unit.contracts:
            for f in c.functions:
                try:
                    signature = f.solidity_signature
                except Exception:  # a declaration Slither can't type
                    continue
                key = int.from_bytes(keccak(text=signature)[:4], "big")
                cache.setdefault((key, len(f.parameters)), set()).add(signature)
    found = cache.get((selector, arity), set())
    return next(iter(found)) if len(found) == 1 else None


def _unmasked(word: Term) -> Term:
    """An address cleaned to its 20 bytes (``and(from, shr(96, not(0)))``) as the address."""
    if word[:2] == ("op", "and") and len(word[2]) == 2:
        for x, y in (word[2], word[2][::-1]):
            if y[0] == "const" and y[1] == 2**160 - 1:
                return x
    return word


def _encoded_action(target: Term, data: Term, value: Term) -> Term | None:
    """The action an assembly ``call`` sends no ether with, ``add(data, 0x20)`` being ``abi.encodeWithSignature``
    data: the same call a high-level one would be, made to ``target``."""
    if _small_const(value) != 0 or not (isinstance(data, tuple) and data[:2] == ("op", "add")):
        return None
    encoded = [a for a in data[2] if a[0] == "enc"]
    if len(encoded) != 1 or not any(a[0] == "const" and a[1] == 32 for a in data[2]):
        return None
    call = _view_call(target, encoded[0])
    return None if call is None else mk("call", call[1], call[2], call[3], False)


def _view_call(target: Term, data: Term) -> Term | None:
    """The view call ``data`` encodes (``abi.encodeWithSignature``), made to ``target``."""
    if data[1] != "abi.encodeWithSignature" or not data[2] or data[2][0][0] != "const":
        return None
    signature = data[2][0][1]
    if not isinstance(signature, str) or "(" not in signature:
        return None
    return mk("call", target, signature, tuple(data[2][1:]), True)


def _lost_word(name: str, args: Any) -> Term:
    """A memory word read back where the lowering lost track of what was written (an ``mstore`` at an offset it
    can't place): anything, the caller's address included, so an unknown it marks for no one rides along."""
    return mk("opaque", name, (*args, unknown("memory")))


def _extend(loc: tuple, step: tuple) -> tuple:
    contract, name, path = loc
    return (contract, name, (*path, step))


# What a caller steers: who they are and what they send.
_STEERING = frozenset({"caller", "origin", "signer", "arg", "len", "elem", "callvalue", "calldatasize", "sig"})
_IDENTITIES = frozenset({"caller", "origin", "signer"})


def _loop_nodes(start: Any, leave: Any) -> list:
    """The nodes of the loop entered at ``start`` and left through ``leave``: everything reachable from ``start``
    without passing ``leave`` (a ``break`` jumps there, a ``return`` ends the path inside)."""
    seen = {id(start)}
    out = [start]
    stack = [start]
    while stack:
        node = stack.pop()
        for son in node.sons:
            if son is leave or id(son) in seen:
                continue
            seen.add(id(son))
            out.append(son)
            stack.append(son)
    return out


def _reference_typed(type_: Any) -> bool:
    """An array, ``bytes``/``string`` or struct: a value memory holds by reference."""
    from slither.core.declarations import Structure
    from slither.core.solidity_types import ArrayType, UserDefinedType

    return (
        isinstance(type_, ArrayType)
        or _bytes_typed(type_)
        or (isinstance(type_, UserDefinedType) and isinstance(type_.type, Structure))
    )


def _conjuncts(pc: Term) -> set:
    return set(pc[1]) if pc[0] == "and" else {pc}


def _constant(var: Constant) -> Term:
    type_ = str(var.type)
    value = var.value
    if isinstance(value, bool):
        return const(value, "bool")
    if isinstance(value, str):
        if type_ == "address" or (value.startswith("0x") and type_ != "string"):
            try:
                return const(int(value, 16), type_)
            except ValueError:
                return const(value, type_)
        if type_.startswith("bytes") and type_[5:].isdigit() and value.isdigit():
            # A ``bytesN`` Slither computed (a selector, an interface id) is written as its decimal number; a literal
            # is typed ``string`` until converted.
            return const(int(value), type_)
        aligned = _fixed_bytes(value.encode(), type_)
        return const(aligned, type_) if aligned is not None else const(value, type_)
    return const(int(value), type_)


def _fixed_bytes(raw: bytes, type_: str) -> int | None:
    """A string or ``hex"..."`` literal's bytes typed ``bytesN``: left-aligned in N bytes, as Solidity stores it."""
    if not (type_.startswith("bytes") and type_[5:].isdigit()):
        return None
    width = int(type_[5:])
    return int.from_bytes(raw.ljust(width, b"\0"), "big") if len(raw) <= width else None


_FILES: dict[str, bytes | None] = {}


def _source(item: Any, fits: Any = None) -> str:
    """The source text of a node or expression: the first reading ``fits`` accepts. solc's offsets count the bytes
    of the file as it was compiled, which may differ from the file at hand in line ends alone (``\r\n`` turned into
    ``\n`` either before compiling or when Slither read it), so Slither's own slice, the file's bytes and the file's
    bytes with ``\n`` line ends are all tried. Empty when none fits."""
    mapping = getattr(item, "source_mapping", None)
    if mapping is None:
        return ""
    try:
        readings = [getattr(mapping, "content", "") or ""]
    except UnicodeDecodeError:  # Slither's slice cut through a multi-byte character: the file's bytes below
        readings = [""]
    path = getattr(getattr(mapping, "filename", None), "absolute", None)
    if path is not None and path not in _FILES:
        try:
            with open(path, "rb") as handle:
                _FILES[path] = handle.read()
        except OSError:
            _FILES[path] = None
    raw = _FILES.get(path) if path is not None else None
    if raw is not None:
        for text in (raw, raw.replace(b"\r\n", b"\n")):
            readings.append(text[mapping.start : mapping.start + mapping.length].decode("utf8", errors="replace"))
    if fits is None:
        return readings[0]
    return next((r for r in readings if fits(r)), "")


def _literal_bytes(value: str, source: str) -> bytes | None:
    """A string literal's bytes: a ``hex"..."`` one's from its source (Slither's value decodes them as text, which
    not every byte sequence survives), any other's as UTF-8."""
    if not source.startswith("hex"):
        return value.encode()
    digits = source[3:].strip().strip("'\"").replace("_", "")
    try:
        return bytes.fromhex(digits)
    except ValueError:
        return None


def _constant_initializer(var: StateVariable) -> Term:
    """A ``constant``'s value: its initializer folded when it's literal arithmetic, else a named placeholder."""
    value = _fold_expression(var.expression, str(var.type), 0)
    if value is not None and str(var.type).startswith("int") and isinstance(value[1], int):
        return _convert(str(var.type), value)  # a signed constant as the signed number it is
    return value if value is not None else mk("constant", var.name)


def _fold_expression(expr: Any, type_: str, depth: int) -> Term | None:
    from slither.core.expressions import (
        BinaryOperation,
        CallExpression,
        Identifier,
        Literal,
        MemberAccess,
        TupleExpression,
        UnaryOperation,
    )
    from slither.core.expressions import (
        TypeConversion as TypeConv,
    )

    if depth > 16 or expr is None:
        return None
    if isinstance(expr, TupleExpression) and len(expr.expressions) == 1:
        return _fold_expression(expr.expressions[0], type_, depth + 1)
    if isinstance(expr, TypeConv):
        inner = _fold_expression(expr.expression, str(expr.type), depth + 1)
        return _convert(str(expr.type), inner) if inner is not None else None
    if isinstance(expr, Literal):
        value = expr.value
        if str(expr.type) == "bool" or type_ == "bool":
            return const(value in (True, "true"), "bool")
        if isinstance(value, str) and str(expr.type) == "string":
            source = _source(expr, lambda text: text.startswith(("hex", '"', "'")))
            raw = _literal_bytes(value, source)
            aligned = _fixed_bytes(raw, type_) if raw is not None else None
            return const(aligned, type_) if aligned is not None else const(value, "string")
        try:
            number = int(value, 0) if isinstance(value, str) else int(value)
        except (TypeError, ValueError):
            from slither.utils.integer_conversion import convert_string_to_int

            try:
                number = convert_string_to_int(value)  # ``1e27``, ``1_000``, exactly (a float would round)
            except Exception as exc:  # Slither's parse errors; never the decision's own timeout
                if isinstance(exc, TimeoutError):
                    raise
                return const(value, "string")
        unit = {"ether": 10**18, "gwei": 10**9, "wei": 1, "days": 86400, "hours": 3600, "minutes": 60, "weeks": 604800}
        return const(number * unit.get(str(getattr(expr, "subdenomination", None) or ""), 1), type_ or "uint256")
    if isinstance(expr, Identifier) and (
        isinstance(expr.value, TopLevelVariable) or (isinstance(expr.value, StateVariable) and expr.value.is_constant)
    ):
        return _fold_expression(expr.value.expression, str(expr.value.type), depth + 1)
    if isinstance(expr, UnaryOperation):
        inner = _fold_expression(expr.expression, type_, depth + 1)
        if inner is None or not isinstance(inner[1], int):
            return None
        op = str(expr.type)
        if op in ("~", "UnaryOperationType.TILD"):
            name = str(inner[2])
            bits = int(name[4:]) if name.startswith("uint") and name[4:].isdigit() else 256
            return const((2**bits - 1 - inner[1]) % 2**bits, name)
        if op in ("-", "UnaryOperationType.MINUS_PRE"):
            return const((-inner[1]) % 2**256, type_)
        return None
    if isinstance(expr, BinaryOperation):
        a = _fold_expression(expr.expression_left, type_, depth + 1)
        b = _fold_expression(expr.expression_right, type_, depth + 1)
        if a is None or b is None or not isinstance(a[1], int) or not isinstance(b[1], int):
            return None
        names = {
            "+": "add",
            "-": "sub",
            "*": "mul",
            "/": "div",
            "%": "mod",
            "**": "pow",
            "<<": "shl",
            ">>": "shr",
            "&": "and",
            "|": "or",
            "^": "xor",
        }
        op = names.get(str(expr.type))
        folded = mk_op(op, (a, b)) if op else None
        return folded if folded is not None and folded[0] == "const" else None
    if isinstance(expr, MemberAccess) and expr.member_name in ("max", "min") and "type(" in str(expr.expression):
        called = expr.expression
        # ``type(uint256)``, which Slither renders ``type()(uint256)``: the type is the call's one argument.
        inner = str(called.arguments[0]) if isinstance(called, CallExpression) and called.arguments else ""
        if inner.startswith("uint"):
            bits = int(inner[4:] or 256)
            return const(2**bits - 1 if expr.member_name == "max" else 0, inner)
        if inner.startswith("int"):
            bits = int(inner[3:] or 256)
            return const(2 ** (bits - 1) - 1 if expr.member_name == "max" else (-(2 ** (bits - 1))) % 2**256, inner)
        return None
    if isinstance(expr, CallExpression) and str(expr.called).split("(")[0] in _HASHES:
        args = []
        for a in expr.arguments:
            if isinstance(a, Literal):
                args.append(const(a.value, "string"))
            else:
                return None
        if str(expr.called).startswith(("keccak256", "sha3")) and len(args) == 1 and isinstance(args[0][1], str):
            # A literal's hash is a number (``keccak256("eip1967.proxy.admin") - 1``), so arithmetic on it folds too.
            from eth_utils import keccak

            return const(int.from_bytes(keccak(text=args[0][1]), "big"), "bytes32")
        return mk("hash", "keccak256", tuple(args))
    return None


def _convert(type_: str, value: Term, source: Any = None) -> Term:
    """``value`` converted to ``type_`` (from ``source``'s type when known): an integer kept to the new width (read as
    signed for a signed type), a ``bytesM`` cut or padded on the right to ``bytesN`` (its value right-aligned, so a
    shift), the first ``N`` bytes of a ``bytes`` value; any other conversion leaves the value as it is."""
    from slither.core.solidity_types import ElementaryType

    src = str(source) if source is not None else None
    if type_ == "bytes4" and value == CALLDATA:
        return mk("sig")  # ``bytes4(msg.data[0:4])``: the selector this call came in with
    target = _integer(type_) if re.fullmatch(r"u?int\d*|bytes\d+", type_) else None
    shift = None
    if target is not None and src is not None and type_.startswith("bytes") and re.fullmatch(r"bytes\d+", src):
        shift = 8 * (int(type_[5:]) - int(src[5:]))  # a ``bytesM`` to ``bytesN``: positive pads, negative cuts
    if target is not None and src in ("bytes", "string"):
        if type_.startswith("bytes"):
            return mk_slice(mk("elem", value, const(0)), 0, int(type_[5:]))  # its first N bytes
        return unknown(f"unsupported:conversion:{src}->{type_}")
    if value[0] == "const" and isinstance(value[1], int) and not isinstance(value[1], bool):
        if shift is not None:
            moved = value[1] << shift if shift >= 0 else value[1] >> -shift
            return const(moved % 2 ** target[0], type_)
        if target is not None:
            bits, is_signed = target
            return const(_signed(value[1], bits) if is_signed else value[1] % 2**bits, type_)
        if type_ in ("address", "address payable"):
            return const(value[1] % 2**160, type_)
        return const(value[1], type_)
    if shift is not None:
        if shift == 0:
            return value
        if shift > 0:
            return mk_op("shl", (value, const(shift)))
        return mk("conv", type_, mk_op("shr", (value, const(-shift))))
    unsigned_wide = target is None or (target[0] >= 160 and not target[1])
    if value[0] in ("caller", "origin", "this") and unsigned_wide:
        return value
    if target is not None and src is not None and isinstance(source, ElementaryType):
        widened = _integer(src)
        bits, is_signed = target
        same_kind = src.startswith("bytes") == type_.startswith("bytes")
        if same_kind and widened[0] <= bits and (widened[1] == is_signed or (not widened[1] and widened[0] < bits)):
            return value  # wider, or unsigned into a wider signed type: every value fits as it is
    if type_ in ("uint256", "bytes32") and (src is None or not str(src).startswith("int")):
        return value  # a word read as a word
    if type_ == "int256" and src is not None and re.fullmatch(r"int\d*", str(src)):
        return value
    return mk("conv", type_, value)


def _signed(x: int, bits: int) -> int:
    r = x % 2**bits
    return r - 2**bits if r >= 2 ** (bits - 1) else r


def _zero(type_: Any, depth: int = 0) -> Term:
    from slither.core.declarations import Structure
    from slither.core.solidity_types import ArrayType, UserDefinedType

    name = str(type_) if type_ is not None else ""
    if isinstance(type_, ArrayType) and type_.is_fixed_array:
        # ``T[n] memory x``: n zeroed items, whatever is written to them later followed.
        length = type_.length_value
        size = int(str(length.value)) if length is not None and str(length.value).isdigit() else None
        return _new_array(const(size, "uint256")) if size is not None else mk("array", unknown("length"))
    if name == "bool":
        return const(False, "bool")
    if isinstance(type_, (ElementaryType,)) or name.startswith(("uint", "int", "address", "bytes")):
        return const(0, name or "uint256")
    if isinstance(type_, MappingType):
        return unknown("memory_mapping")
    if isinstance(type_, UserDefinedType) and isinstance(type_.type, Structure) and depth < 4:
        # ``S memory s;``: every field zero, set one by one after.
        fields = type_.type.elems_ordered
        return mk("struct", tuple(f.name for f in fields), tuple(_zero(f.type, depth + 1) for f in fields))
    return const(0, name or "uint256")


__all__ = ["Lowerer", "SolidityFunction"]
