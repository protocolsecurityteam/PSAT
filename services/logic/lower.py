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
from slither.slithir.operations.lvalue import OperationWithLValue
from slither.slithir.variables import Constant, ReferenceVariable

from .terms import (
    CALLDATA,
    CALLER,
    FALSE,
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
    stable,
    subterms,
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
    "tx.gasprice": mk("time", "basefee"),  # at least the base fee; the caller may pay more
}
_HASHES = ("keccak256", "sha256", "ripemd160", "sha3")

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


def merge(states: list[State]) -> State:
    if len(states) == 1:
        return states[0]
    pc = mk_or([s.pc for s in states])
    return State(
        pc,
        _merge_maps(states, "env"),
        _merge_maps(states, "store"),
        _merge_ret(states),
        mem=states[0].mem if all(s.mem == states[0].mem for s in states) else (),
    )


def _merge_maps(states: list[Any], attr: str) -> dict:
    keys: dict = {}
    for s in states:
        keys.update(dict.fromkeys(getattr(s, attr)))
    out = {}
    for key in keys:
        # Storage a branch left alone still holds what it held before the call; a local it never set is unset.
        missing = _unwritten(key) if attr == "store" else unknown("unset")
        values = [getattr(s, attr).get(key, missing) for s in states]
        out[key] = _select([s.pc for s in states], values)
    return out


def _acted(st: State, call: Term) -> State:
    """``st`` having called out: a mark in its writes, which merges keep per path like any other write."""
    return State(st.pc, st.env, {**st.store, ("act", call, ()): TRUE}, st.ret, halted=st.halted, mem=st.mem)


def _changes(exit_: Exit) -> Term:
    """When a call ending at ``exit_`` has an effect: where it called out (an ``act`` mark), or where a write differs
    from the value it replaces (``if (quorum != MAX) quorum = MAX`` changes nothing once it is MAX)."""
    return mk_or(
        [
            mk_not(mk_cmp("eq", value, _unwritten(key)))
            for key, value in exit_.store.items()
            if key[0] not in ("transient", "emit")
        ]
    )


def _unwritten(key: tuple) -> Term:
    if key[0] in ("act", "emit"):
        return FALSE  # no call out, and no event, on a path that didn't make it
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
        # The arguments this call came with, in order: what ``msg.data[4:]`` encodes.
        self._arguments: tuple = ()
        # Whether some storage write may have gone unrecorded (code not followed, assembly not read).
        self.lost = False
        self.exits: list = []

    def success(self, function: Function) -> Term:
        """The condition under which an external call to ``function`` returns."""
        self._steps = 0
        args = {id(p): parameter(p, i) for i, p in enumerate(function.parameters)}
        self._calldata_min = _calldata_min(function)
        self._arguments = tuple(args.values())
        exits = self.run(function, State(TRUE, args), 0)
        # The calls that do something: a write that may change what storage held, or a call out.
        self.effective = mk_or([mk_and([e.pc, _changes(e)]) for e in exits])
        # (contract, variable) or ("raw", contract) of everything it may write.
        self.written = frozenset(
            ("raw", k[1]) if k[0] == "raw" else (k[0], k[1])
            for e in exits
            for k in e.store
            if k[0] not in ("act", "transient", "emit")
        )
        self.exits = exits
        return mk_or([e.pc for e in exits])

    def returns(self, function: Function, args: list[Term], pc: Term = TRUE) -> tuple[Term, tuple]:
        """The condition under which ``function`` returns and its return values, ``args`` bound to its parameters."""
        self._steps = 0
        env = {id(p): a for p, a in zip(function.parameters, args)}
        self._arguments = tuple(args)
        exits = self.run(function, State(pc, env), 0)
        if not exits:
            return FALSE, ()
        merged = merge([State(e.pc, {}, e.store, e.ret) for e in exits])
        return merged.pc, merged.ret or ()

    def run(self, function: Function, state: State, depth: int) -> list[Exit]:
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
        self._stack.append(function)
        try:
            return self._run_from(function, function.entry_point, state, depth)
        finally:
            self._stack.pop()

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
        loop_entry: dict[int, State] = {}
        exits: list[Exit] = []
        for node in order:
            arrived = incoming.pop(id(node), None)
            if not arrived:
                continue
            st = merge(arrived)
            self._steps += 1
            if node.type == NodeType.IFLOOP:
                loop_entry[id(node)] = st
            for target, out in self._step(function, node, st, depth, exits, body):
                for succ, kind in edges[id(node)]:
                    if succ is not target:
                        continue
                    if kind == "back":
                        again = self._loop_condition(succ, out, depth)
                        if again == FALSE and succ.son_false is not None:
                            # The loop is done after this iteration: exact, no forgetting.
                            incoming.setdefault(id(succ.son_false), []).append(out)
                        elif again == TRUE and unrolled < MAX_UNROLL and self._steps < UNROLL_BUDGET:
                            # Another iteration whose condition is known: run it, and the rest of the function after it.
                            exits.extend(self._run_from(function, succ, out, depth, body, unrolled + 1))
                        elif succ.son_false is not None and id(succ) in loop_entry:
                            # Either the loop stops here, exactly, or it goes on: for a few more iterations exactly,
                            # then with everything it changes forgotten.
                            stop = State(mk_and([out.pc, mk_not(again)]), out.env, out.store, out.ret)
                            incoming.setdefault(id(succ.son_false), []).append(stop)
                            more = State(mk_and([out.pc, again]), out.env, out.store, out.ret)
                            if unrolled < MAX_SYMBOLIC_UNROLL and self._steps < UNROLL_BUDGET:
                                exits.extend(self._run_from(function, succ, more, depth, body, unrolled + 1))
                            else:
                                more = _havoc(more, loop_entry[id(succ)], succ)
                                incoming.setdefault(id(succ.son_false), []).append(more)
                    else:
                        incoming.setdefault(id(succ), []).append(out)
        return exits

    def _loop_condition(self, header: Any, st: State, depth: int) -> Term:
        """The header's condition evaluated in ``st``, or ``None`` when it isn't a loop header."""
        if header.type != NodeType.IFLOOP:
            return unknown("not_a_loop")
        for ir in header.irs:
            if isinstance(ir, Condition):
                return self.val(ir.value, st)
            st = self._exec(ir, st, depth)
        return unknown("no_condition")

    def _step(self, function: Function, node: Any, st: State, depth: int, exits: list[Exit], body: Any):
        """Run one node; yield (successor, state) pairs. Exits and dead paths yield nothing."""
        if node.type == NodeType.THROW:
            return
        if node.type == NodeType.PLACEHOLDER and body is not None:
            # A modifier's ``_``: the rest of the function, then the modifier's own tail with its locals.
            for done in body(st):
                after = State(done.pc, st.env, done.store, done.ret)
                if node.sons:
                    yield from self._succeed(node, after, node.sons)
                else:
                    exits.append(Exit(after.pc, after.store, after.ret))
            return
        if node.type == NodeType.ASSEMBLY and not node.irs and isinstance(getattr(node, "inline_asm", None), str):
            st = self._legacy_assembly(function, node.inline_asm, st)
            if st.halted:
                exits.append(Exit(st.pc, st.store, st.ret))
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
        self._node = node
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
                exits.append(Exit(st.pc, st.store, st.ret))
                return
        if node.type in (NodeType.IF, NodeType.IFLOOP) and cond is not None:
            if node.son_true is not None:
                yield node.son_true, replace(st, pc=mk_and([st.pc, cond]))
            if node.son_false is not None:
                yield node.son_false, replace(st, pc=mk_and([st.pc, mk_not(cond)]))
            return
        if not node.sons:
            ret = st.ret if st.ret is not None else tuple(self.val(r, st) for r in function.returns)
            exits.append(Exit(st.pc, st.store, ret))
            return
        yield from self._succeed(node, st, node.sons)

    def _short_circuit(self, irs: list[Any], binary: Any, st: State, depth: int) -> State:
        left = self.val(binary.variable_left, st)
        guard = mk_not(left) if binary.type == BinaryType.OROR else left
        ran = replace(st, pc=mk_and([st.pc, guard]))
        spans = _short_circuits(irs)
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
                ret = tuple(self.val(r, inner) for r in function.returns)
                return [Exit(at.pc, at.store, ret)]
            return self._run_from(function, rest, inner, depth)

        env = {id(p): self.val(a, st) for p, a in zip(modifier.parameters, ir.arguments)}
        if modifier.entry_point is None or depth > MAX_DEPTH:
            self.lost = True  # whatever the modifier writes goes unrecorded
            return body(State(mk_and([st.pc, unknown(f"unanalysed:{modifier.canonical_name}")]), {}, st.store))
        out = self._run_from(modifier, modifier.entry_point, State(st.pc, env, st.store, None), depth + 1, body)
        # A modifier that returns before ``_`` returns the function's defaults.
        defaults = tuple(_zero(r.type) for r in function.returns)
        return [Exit(e.pc, e.store, e.ret if e.ret is not None else defaults) for e in out]

    # Operations -------------------------------------------------------------------------------------------------------

    def _exec(self, ir: Any, st: State, depth: int) -> State:
        out = self._exec_ir(ir, st, depth)
        if out.mem and not _keeps_memory(ir):
            out = replace(out, mem=())
        return out

    def _exec_ir(self, ir: Any, st: State, depth: int) -> State:
        if isinstance(ir, SolidityCall):
            return self._solidity_call(ir, st)
        if isinstance(ir, (InternalCall, LibraryCall)) and isinstance(ir.function, Function):
            # A ``storage`` parameter is the caller's location, not a copy (``EnumerableSet.contains(set, x)``).
            args = [
                ("loc", loc)
                if getattr(p, "location", None) == "storage" and (loc := self._location(a, st)) is not None
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
            exits = self.run(target, State(st.pc, env, st.store), depth + 1)
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
            return self._write(ir.lvalue, self.val(ir.rvalue, st), st)
        if isinstance(ir, Delete):
            # ``delete m[k]``: Slither's lvalue is ``m`` itself; the entry cleared is ``variable``.
            target = ir.variable if self._location(ir.variable, st) is not None else ir.lvalue
            return self._write(target, _zero(getattr(target, "type", None)), st)
        if isinstance(ir, Binary):
            a, b = self.val(ir.variable_left, st), self.val(ir.variable_right, st)
            if ir.type == BinaryType.ANDAND:
                value = mk_and([a, _ran_under(b, a)])
            elif ir.type == BinaryType.OROR:
                value = mk_or([a, _ran_under(b, mk_not(a))])
            elif ir.type in _COMPARE:
                value = mk_cmp(_COMPARE[ir.type], a, b)
            else:
                value = mk_op(_BINARY.get(ir.type, str(ir.type)), (a, b))
            return self._write(ir.lvalue, value, st)
        if isinstance(ir, Unary):
            a = self.val(ir.rvalue, st)
            return self._write(ir.lvalue, mk_not(a) if ir.type == UnaryType.BANG else mk_op("bnot", (a,)), st)
        if isinstance(ir, TypeConversion):
            return self._write(ir.lvalue, _convert(str(ir.type), self.val(ir.variable, st)), st)
        if isinstance(ir, Index):
            return self._index(ir, st)
        if isinstance(ir, Member):
            return self._member(ir, st)
        if isinstance(ir, NewArray):
            length = self.val(ir.arguments[0], st) if ir.arguments else unknown("array_length")
            return self._write(ir.lvalue, _new_array(length), st)
        if isinstance(ir, NewElementaryType):
            # ``new bytes(n)``: n zero bytes, whose length is what code reads back.
            length = self.val(ir.arguments[0], st) if ir.arguments else unknown("bytes_length")
            return self._write(ir.lvalue, mk("array", length), st)
        if isinstance(ir, NewStructure):
            # ``S(a, b)``: its fields by name, so reading one back gives what was put there.
            names = tuple(m.name for m in ir.structure.elems_ordered)
            values = tuple(self.val(a, st) for a in ir.arguments)
            if len(names) == len(values):
                return self._write(ir.lvalue, mk("struct", names, values), st)
        if isinstance(ir, InitArray):
            if len(ir.init_values) == 1 and getattr(ir.lvalue, "location", None) == "storage":
                # ``T[] storage list = s.items``, which Slither renders as an array literal: a pointer to storage.
                pointed = self._location(ir.init_values[0], st)
                if pointed is not None:
                    return self._bind(ir.lvalue, ("loc", pointed), st)
            values = [self.val(v, st) for v in ir.init_values]
            if len(values) == 1 and _array_shaped(values[0]):
                return self._write(ir.lvalue, values[0], st)  # ``T[] memory r = new T[](n)``, as Slither renders it
            return self._write(ir.lvalue, mk("array", const(len(values), "uint256"), tuple(values)), st)
        if isinstance(ir, Length):
            held = self.val(ir.value, st) if self._location(ir.value, st) is None else None
            if held is not None and held[0] == "array":
                return self._write(ir.lvalue, held[1], st)
            if held is not None and held[0] == "code":
                return self._write(ir.lvalue, mk("codesize", held[1]), st)
            if held == CALLDATA:
                return self._write(ir.lvalue, mk("calldatasize", self._calldata_min), st)
            base = self._location(ir.value, st)
            if base is not None:
                # A storage array's length is a slot of its own, read and (before solc 0.6, ``a.length++``) written
                # through this reference.
                return self._bind(ir.lvalue, ("loc", _extend(base, ("f", "length"))), st)
            return self._write(ir.lvalue, mk("len", self.val(ir.value, st)), st)
        if isinstance(ir, CodeSize):
            return self._write(ir.lvalue, mk("codesize", self.val(ir.value, st)), st)  # ``a.code.length``
        if isinstance(ir, EventCall):
            # An event, as a mark in the writes like a call out: which writes each path logs (``write_log``).
            args = tuple(self.val(a, st) for a in ir.arguments)
            return State(st.pc, st.env, {**st.store, ("emit", str(ir.name), args): TRUE}, st.ret, mem=st.mem)
        if isinstance(ir, HighLevelCall) and not isinstance(ir, LibraryCall):
            return self._external_call(ir, st)
        if isinstance(ir, Unpack):
            whole = self.val(ir.tuple, st)
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
            if name == "delegatecall":
                target = self.val(ir.destination, st)
                data = self.val(ir.arguments[0], st) if ir.arguments else CALLDATA
                # Forwarding this call's own data (a proxy), or calling something else with data of its own.
                success = mk("delegate", target) if data == CALLDATA else mk("delegate", target, data)
            else:
                success = mk("assumed", name)  # an action the caller arranges, like a transfer
            inputs = (self.val(ir.destination, st), *(self.val(a, st) for a in ir.arguments))
            # What an arranged action returns is arranged with it (``SafeERC20`` decoding ``true``).
            returned = mk("assumed", "returndata") if success[0] == "assumed" else mk("opaque", "returndata", inputs)
            return self._write(ir.lvalue, ("tuple", (success, returned)), st)
        if isinstance(ir, NewContract):
            # Code deployed by this call: an effect whatever the new contract's constructor does.
            st = _acted(st, mk("assumed", f"create:{id(ir)}"))
            return self._write(ir.lvalue, unknown("created"), st) if ir.lvalue is not None else st
        if isinstance(ir, InternalDynamicCall):
            if ir.lvalue is not None:
                inputs = tuple(self.val(a, st) for a in ir.arguments)
                return self._write(ir.lvalue, mk("opaque", f"dynamic:{id(ir)}", inputs), st)
            return st
        if isinstance(ir, OperationWithLValue) and ir.lvalue is not None:
            return self._write(ir.lvalue, unknown(type(ir).__name__), st)
        return st

    def _solidity_call(self, ir: SolidityCall, st: State) -> State:
        name = ir.function.name
        base = name.split("(", 1)[0]
        args = [self.val(a, st) for a in ir.arguments]
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
        if base in ("log1", "log2", "log3", "log4") and len(args) >= 3:
            # An event written in assembly (DSS's ``note``): a mark like ``emit``'s, its topics as the arguments.
            topics = tuple(mk("sig") if _selector_word(t) else t for t in args[2:])
            return State(st.pc, st.env, {**st.store, ("emit", base, topics): TRUE}, st.ret, mem=st.mem)
        if base == "staticcall" and len(args) == 6:
            return self._static_call(ir, args, st)
        if base == "call" and len(args) == 7:
            action = _encoded_action(args[1], args[3], args[2]) or self._scratch_action(st.mem, args)
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
            after = State(st.pc, st.env, st.store, st.ret, mem=mem)
            return self._write(ir.lvalue, mk("assumed", base), after) if ir.lvalue is not None else after
        if base == "delegatecall":
            # ``delegatecall(gas, target, ...)``: the target's code for this call, on this storage, for this caller.
            value = mk("delegate", args[1] if len(args) > 1 else unknown("delegate_target"))
            return self._write(ir.lvalue, value, st) if ir.lvalue is not None else st
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
                or mk("opaque", name, tuple(args))
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
        elif base.startswith("abi.decode") and args and args[0][0] == "enc" and args[0][1] == "abi.encode":
            words = _static_words(args[0][2])
            types = _decoded_types(ir.lvalue)
            if words is None or types is None:
                value = mk("opaque", name, tuple(args))
            elif len(types) > len(words):
                return State(FALSE, st.env, st.store, st.ret)  # fewer words than it decodes: abi.decode reverts
            else:
                decoded = [_convert(str(t), w) for t, w in zip(types, words)]
                value = decoded[0] if len(decoded) == 1 else ("tuple", tuple(decoded))
        elif base == "ecrecover":
            value = mk("signer", *args)
        elif base == "sload":
            value = mk("rawload", self.this, args[0])
        elif base == "sstore":
            store = dict(st.store)
            store[("raw", self.this, args[0])] = args[1]
            return State(st.pc, st.env, store, st.ret)
        elif base == "tstore" and len(args) == 2:
            store = dict(st.store)
            store[("transient", self.this, args[0])] = args[1]
            return State(st.pc, st.env, store, st.ret, mem=st.mem)
        elif base == "tload" and len(args) == 1:
            # Transient storage is empty when a transaction starts (a reentrancy lock reads zero), save what this call
            # stored there itself.
            value = mk("const", 0, "uint256")
            for key, written in st.store.items():
                if key[0] == "transient":
                    value = mk_ite(mk_cmp("eq", key[2], args[0]), written, value)
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
        return mk("call", args[1], signature, tuple(_unmasked(w) for w in words), False)

    def _static_call(self, ir: SolidityCall, args: list, st: State) -> State:
        """Assembly ``staticcall(gas, to, add(data, 0x20), mload(data), out, size)`` of data an ``abi.encode*`` built:
        the view call it makes, succeeding when the call returns, its return words left at ``out``. OpenZeppelin's
        ``AuthorityUtils.canCallWithDelay`` asks the access manager this way."""
        call = None
        data = args[2]
        if data[0] == "op" and data[1] == "add":
            encoded = [a for a in data[2] if a[0] == "enc"]
            if len(encoded) == 1 and any(a[0] == "const" and a[1] == 32 for a in data[2]):
                call = _view_call(args[1], encoded[0])
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
        value = mk("call", target, signature, args, view)
        returns = getattr(fn, "returns", None) or []
        self._last_call = value
        self._last_returns = len(returns) if isinstance(fn, Function) else None
        if ir.lvalue is None:
            # A call whose result goes unused still has to return: a view call is there for whether it reverts
            # (``registry.onlyAdmin(sender)``), and so may an action be (``supplyControl.canMintToAddress(to, v,
            # msg.sender)``), which the decision assumes unless it is handed the caller.
            st = _acted(st, value) if not view else st
            return State(mk_and([st.pc, mk("ok", value, self._last_returns)]), st.env, st.store, st.ret)
        if not view:
            st = _acted(st, value)
            # An action has to return whether or not its result is read (``token.transferFrom`` returns a bool few
            # check): the same revert point as above.
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
        return self.val(var, st)

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
                return self.val(names[token], st)
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
        assigned = set(re.findall(r"(\w+)\s*:=", asm)) | set(re.findall(r"let\s+(\w+)", asm))
        for name in assigned:
            if name in names:
                st = self._bind(names[name], unknown(f"asm:{name}"), st)
        for target, source in re.findall(r"(\w+)\s*:=\s*(\w+)\s*(?=$|\n|\}|let\b|\w+\s*:=|mstore|sstore)", asm):
            # A plain copy (``output := _input``): the value itself, unless the target is assigned again elsewhere.
            if target in names and len(re.findall(rf"\b{target}\s*:=", asm)) == 1:
                st = self._bind(names[target], value(source), st)
        for target, slot in re.findall(r"(\w+)\s*:=\s*sload\(\s*(\w+)\s*\)", asm):
            if target in names:
                st = self._bind(names[target], mk("rawload", self.this, value(slot)), st)
        for target, account in re.findall(r"(\w+)\s*:=\s*extcodesize\(\s*(\w+)\s*\)", asm):
            if target in names:
                st = self._bind(names[target], mk("codesize", value(account)), st)
        if len(re.findall(r"\bsstore\(", asm)) > len(re.findall(r"sstore\(\s*(\w+)\s*,\s*(\w+)\s*\)", asm)):
            self.lost = True
        for slot, written in re.findall(r"sstore\(\s*(\w+)\s*,\s*(\w+)\s*\)", asm):
            store = dict(st.store)
            store[("raw", self.this, value(slot))] = value(written)
            st = State(st.pc, st.env, store, st.ret)
        for found in re.finditer(r"\blog([1-4])\s*\(", asm):
            parts = _call_arguments(asm, found.end())
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
        compare = {"lt": "lt", "gt": "gt", "eq": "eq", "slt": None, "sgt": None}

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
            if name in compare and len(args) == 2 and compare[name]:
                return mk_cmp(compare[name], args[0], args[1])
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
            if name in (
                "mload",
                "byte",
                "keccak256",
                "sar",
                "signextend",
                "addmod",
                "mulmod",
                "sdiv",
                "smod",
                "gas",
                "returndatasize",
                "calldatasize",
                "chainid",
                "selfbalance",
                "balance",
                "msize",
            ):
                return mk("opaque", f"{name}(uint256)" if name == "mload" else name, tuple(args))
            raise Unsupported(f"builtin {name}")

        for statement in statements:
            if isinstance(statement, Assign):
                if len(statement.targets) != 1:
                    raise Unsupported("several targets")
                target = statement.targets[0]
                term = const(0) if statement.value is None else ev(statement.value)
                if target in local or target not in names:
                    local[target] = term
                else:
                    st = self._bind(names[target], term, st)
                continue
            call = statement.call
            if call.name == "sstore" and len(call.args) == 2:
                slot, written = ev(call.args[0]), ev(call.args[1])
                st = State(st.pc, st.env, {**st.store, ("raw", self.this, slot): written}, st.ret)
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
        base = self._location(ir.variable_left, st)
        key = self.val(ir.variable_right, st)
        if base is not None:
            return self._bind(ir.lvalue, ("loc", _extend(base, ("k", key))), st)
        held = self.val(ir.variable_left, st)
        if _items(held) is not None and key[0] == "const" and 0 <= key[1] < len(held[2]):
            # An element of a memory array this call made: reads and writes go to the array's own items.
            return self._bind(ir.lvalue, ("mref", id(ir.variable_left), key[1]), st)
        return self._write(ir.lvalue, mk("elem", held, key), st)

    def _member(self, ir: Member, st: State) -> State:
        field_name = str(getattr(ir.variable_right, "value", ir.variable_right))
        base = self._location(ir.variable_left, st)
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
        if isinstance(whole, tuple) and whole and whole[0] == "struct" and field_name in whole[1]:
            if ir.lvalue is not None:
                # A field of a memory struct: read from, and written back into, the struct this call holds.
                self._structs[id(ir.variable_left)] = ir.variable_left
                return self._bind(ir.lvalue, ("sref", id(ir.variable_left), field_name), st)
            return self._write(ir.lvalue, whole[2][whole[1].index(field_name)], st)
        if isinstance(whole, tuple) and whole and whole[0] == "load":
            # A field of a struct read whole from storage (``Config memory c = _config; c.epoch``): that field's slot.
            return self._write(ir.lvalue, mk("load", whole[1], whole[2], (*whole[3], ("f", field_name))), st)
        if isinstance(whole, tuple) and whole and whole[0] == "arg" and ir.lvalue is not None:
            # A field of a struct the caller passes is a value the caller picks, like any argument.
            return self._write(ir.lvalue, _typed_arg(f"{whole[1]}.{field_name}", ir.lvalue.type), st)
        if field_name in ("codesize", "codehash") and _address_typed(getattr(ir.variable_left, "type", None)):
            return self._write(ir.lvalue, mk(field_name, whole), st)  # ``address(token).code.length``
        value = mk("op", "field", (whole, const(field_name, "string")))
        return self._write(ir.lvalue, value, st)

    def _location(self, var: Any, st: State) -> tuple | None:
        if isinstance(var, StateVariable) and not (var.is_constant or var.is_immutable):
            return (self.this, var.name, ())
        held = st.env.get(id(var))
        if isinstance(held, tuple) and held and held[0] == "loc":
            return held[1]
        return None

    def _read_at(self, loc: tuple, st: State) -> Term:
        """Storage at ``loc`` as this call sees it: earlier writes whose keys may equal it, over the pre-call value."""
        contract, name, path = loc
        value: Term = mk("load", contract, name, path)
        for key, written in st.store.items():
            if key[0] == "raw" or key[0] != contract or key[1] != name or len(key[2]) != len(path):
                continue
            same = []
            for (kind_a, a), (kind_b, b) in zip(key[2], path):
                if kind_a != kind_b:
                    same = [FALSE]
                    break
                same.append(mk_cmp("eq", a, b) if kind_a == "k" else (TRUE if a == b else FALSE))
            value = mk_ite(mk_and(same), written, value)
        return value

    def _bind(self, lvalue: Any, value: Any, st: State) -> State:
        env = dict(st.env)
        env[id(lvalue)] = value
        return State(st.pc, env, st.store, st.ret, mem=st.mem)

    def _write(self, lvalue: Any, value: Any, st: State) -> State:
        ref = st.env.get(id(lvalue))
        if isinstance(ref, tuple) and ref and ref[0] == "mref":
            array = st.env.get(ref[1])
            if _items(array) is not None:
                items = (*array[2][: ref[2]], value, *array[2][ref[2] + 1 :])
                env = {**st.env, ref[1]: mk("array", array[1], items)}
                return State(st.pc, env, st.store, st.ret, mem=st.mem)
            return self._bind(lvalue, value, st)
        if isinstance(ref, tuple) and ref and ref[0] == "sref":
            struct = self._structs[ref[1]]
            whole = self.val(struct, st)
            if isinstance(whole, tuple) and whole and whole[0] == "struct" and ref[2] in whole[1]:
                at = whole[1].index(ref[2])
                return self._write(struct, mk("struct", whole[1], (*whole[2][:at], value, *whole[2][at + 1 :])), st)
            return self._bind(lvalue, value, st)
        loc = self._location(lvalue, st)
        if loc is not None:
            store = dict(st.store)
            store[loc] = value
            return State(st.pc, st.env, store, st.ret, mem=st.mem)
        return self._bind(lvalue, value, st)

    # Values -----------------------------------------------------------------------------------------------------------

    def _arguments_only(self) -> bool:
        """Whether every ``msg.data`` in this statement is ``msg.data[4:]``, the arguments without the selector,
        which Slither's IR renders as ``msg.data`` itself; read from the source."""
        source = _source(self._node, lambda text: "msg.data" in text)
        uses = source.count("msg.data")
        return uses > 0 and len(_ARGUMENTS_SLICE.findall(source)) == uses

    def val(self, var: Any, st: State) -> Any:
        if isinstance(var, Constant):
            return _constant(var)
        if isinstance(var, (SolidityVariableComposed, SolidityVariable)):
            if var.name == "msg.sender":
                return self.sender
            if var.name == "this":
                return self.this
            if var.name == "msg.data" and self._arguments_only():
                return mk("enc", "abi.encode", self._arguments)
            return _ENVIRONMENT.get(var.name, unknown(var.name))
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
            array = st.env.get(held[1])
            return array[2][held[2]] if _items(array) is not None else unknown("memory")
        if isinstance(held, tuple) and held and held[0] == "sref":
            whole = self.val(self._structs[held[1]], st)
            if isinstance(whole, tuple) and whole and whole[0] == "struct" and held[2] in whole[1]:
                return whole[2][whole[1].index(held[2])]
            return unknown("memory")
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
    # A back edge to a loop header delivers to the header's exit, so it orders the latch before the exit.
    indegree = dict.fromkeys(nodes, 0)
    successors: dict[int, list[Any]] = {k: [] for k in nodes}
    for key, out in edges.items():
        for son, kind in out:
            target = son if kind == "forward" else son.son_false
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


def _extend(loc: tuple, step: tuple) -> tuple:
    contract, name, path = loc
    return (contract, name, (*path, step))


def _havoc(state: State, entry: State | None, header: Any) -> State:
    """The state after more iterations of the loop at ``header``: what the body changed is unknown from here, though
    still dependent on whichever identities one iteration made it depend on."""
    if entry is None:
        return state
    changed = [v for k, v in state.env.items() if entry.env.get(k) != v]
    changed += [v for k, v in state.store.items() if entry.store.get(k) != v]
    added = _conjuncts(state.pc) - _conjuncts(entry.pc)
    # A loop whose iterations neither the caller nor the arguments steer (a sum over a stored list) ends the same way
    # whoever calls: its remainder is unknown, but singles out nobody.
    anyone = not any(isinstance(v, tuple) and contains(v, _STEERING) for v in [*changed, *added])
    # One the arguments steer but not who calls (running a proposal's calls): how it ends depends on what is asked,
    # never on who asks.
    nobody = not any(isinstance(v, tuple) and contains(v, _IDENTITIES) for v in [*changed, *added])
    tag = f"loop:{header.node_id}" + (":anyone" if anyone else ":nobody" if nobody else "")

    def forget(value: Any) -> Any:
        if not isinstance(value, tuple) or not value or not isinstance(value[0], str) or value[0] == "loc":
            return unknown(tag)
        roots = tuple(sorted({t for kind in ("caller", "origin", "signer") for t in subterms(value, kind)}, key=stable))
        return mk("opaque", tag, roots)

    env = {k: (v if entry.env.get(k) == v else forget(v)) for k, v in state.env.items()}
    # A call out stays made, however many times the loop runs.
    store = {
        k: (v if entry.store.get(k) == v or k[0] in ("act", "emit") else forget(v)) for k, v in state.store.items()
    }
    return State(mk_and([state.pc, unknown(tag)]), env, store, state.ret)


# What a caller steers: who they are and what they send.
_STEERING = frozenset({"caller", "origin", "signer", "arg", "len", "elem", "callvalue", "calldatasize", "sig"})
_IDENTITIES = frozenset({"caller", "origin", "signer"})


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
    readings = [getattr(mapping, "content", "") or ""]
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


def _convert(type_: str, value: Term) -> Term:
    if type_ == "bytes4" and value == CALLDATA:
        return mk("sig")  # ``bytes4(msg.data[0:4])``: the selector this call came in with
    if value[0] == "const" and isinstance(value[1], int):
        width = {"address": 160, "uint160": 160, "bytes4": 32, "uint8": 8, "uint32": 32, "uint64": 64}.get(type_)
        if width:
            return const(value[1] % (2**width), type_)
        return const(value[1], type_)
    if type_ in ("uint256", "bytes32", "int256") or value[0] in ("caller", "origin", "this"):
        return value
    return mk("conv", type_, value)


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
