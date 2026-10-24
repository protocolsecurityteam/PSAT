"""One function's verdict: lower it, find who satisfies the formula, and whether that list is everyone."""

from __future__ import annotations

import itertools
import math
import os
import re
from collections.abc import Callable
from dataclasses import replace
from typing import Any

from eth_utils.crypto import keccak

from .decide import (
    _EXECUTED_CANDIDATES,
    _OTHER_STRANGERS,
    ANY_KEY,
    FRESH,
    IDENTITY_DEPTH,
    LOG_SECONDS,
    LOG_TOTAL_SECONDS,
    NODE_WORK,
    RAW_SLOT,
    UNK,
    Chain,
    Evaluator,
    Verdict,
    World,
    _runtime_code,
    contains_term,
    coverage,
    decide,
    gate_of,
    runs,
    strangers_run,
    when_atoms,
)
from .decide import _size as _size_of
from .immutables import immutable_offsets, immutable_value
from .logged import keyed_by, logged, logged_raw, members, written_by
from .lower import Lowerer, parameter
from .scope import classify, contract_facts
from .snapshot import creation_keys
from .taint import tainted
from .terms import (
    CALLER,
    FALSE,
    IDENTITY_KINDS,
    THIS,
    TRUE,
    Term,
    assume_conjuncts,
    conjuncts,
    contains,
    mk,
    mk_and,
    mk_not,
    replace_terms,
    stable,
    substitute,
    subterms,
    unknown,
)


def _event_args(spec: dict, topics: list[int], data: list[int]) -> dict[int, int]:
    """Argument position -> 32-byte word: indexed arguments from the topics, the rest from the data in order."""
    indexed = list(spec.get("indexed_positions") or [])
    count = (
        max([*indexed, spec.get("value_position") or 0, *(spec.get("key_positions_by_index") or {}).values(), 0]) + 1
    )
    out: dict[int, int] = {}
    data_index = 0
    for position in range(count + len(data)):
        if position in indexed:
            slot = 1 + indexed.index(position)
            if slot < len(topics):
                out[position] = topics[slot]
        else:
            if data_index < len(data):
                out[position] = data[data_index]
            data_index += 1
    return out


def _writer_events(contract: Any, var: str) -> set[str]:
    """Signatures of the events emitted by entry points that write ``var``, through internal calls too."""
    from slither.slithir.operations import EventCall

    by_name: dict[str, set[str]] = {}
    for event in contract.events:
        by_name.setdefault(event.name, set()).add(event.full_name)
    out: set[str] = set()
    for function in contract.functions_entry_points:
        written = {v.name for v in function.all_state_variables_written()}
        if var not in written:
            continue
        for ir in function.all_slithir_operations():
            if isinstance(ir, EventCall):
                out |= by_name.get(str(ir.name), set())
    return out


def _address_literals(contract: Any) -> set[int]:
    from slither.slithir.variables import Constant

    from .lower import _constant_initializer

    out: set[int] = set()
    for var in contract.state_variables_ordered:
        if var.is_constant and str(var.type) == "address":
            value = _constant_initializer(var)
            if value[0] == "const" and isinstance(value[1], int):
                out.add(value[1])
    for function in [*contract.functions, *contract.modifiers]:
        for node in function.nodes:
            for ir in node.irs:
                for value in getattr(ir, "read", []) or []:
                    if isinstance(value, Constant) and str(value.type) == "address":
                        raw = value.value
                        out.add(int(raw, 16) if isinstance(raw, str) else int(raw))
    return out


_MAX_LATCH_STATES = 64
_REACH_ROUNDS = 8  # rounds of writes followed from the current value; past them, nothing is assumed latched


def _written_values(contract: Any, loads: list[Term]) -> dict[tuple, list | None] | None:
    """(variable, path) -> each write the entry points that may write ``loads`` make there, as (the writer's path
    condition, the constants it can leave or ``None`` when it can leave something else, the value written). ``None``
    overall when
    storage can change beyond what the lowering sees: an assembly store wherever the caller says, or a delegatecall into
    code the contract itself keeps (a diamond's facets). A delegatecall into code the caller names (a Safe transaction,
    an upgrade) runs arbitrary code: that is the power of whoever may make the call, reported on that function, not a
    path this contract's logic offers to reopen a condition."""
    from slither.core.cfg.node import NodeType

    writers = [f for f in contract.functions_entry_points if not (f.view or f.pure or f.is_constructor)]
    cache = contract.__dict__.setdefault("_psat_stores", {})
    if "delegating" not in cache:
        cache["delegating"] = [
            f
            for f in writers
            if any("delegatecall" in str(c) for c in [*f.all_low_level_calls(), *f.all_solidity_calls()])
            or any(n.type == NodeType.ASSEMBLY and "delegatecall" in str(n.inline_asm or "") for n in f.all_nodes())
        ]
    for fn in cache["delegating"]:
        exits = _stores(contract, fn, cache)
        if exits is None or any(
            not (_arbitrary(d) or _own_code(d)) for pc, store in exits for d in _delegates(pc, store)
        ):
            return None
    names = {t[2] for t in loads if t[0] == "load" and isinstance(t[2], str)}
    pointer = any(t[0] == "rawload" or not isinstance(t[2], str) for t in loads)
    out: dict[tuple, list | None] = {}
    for fn in writers:
        written = {v.name for v in fn.all_state_variables_written()} | _by_reference(fn)
        uses_assembly = pointer and any(n.type == NodeType.ASSEMBLY for n in fn.all_nodes())
        if not (names & written) and not uses_assembly:
            continue
        exits = _stores(contract, fn, cache)
        if exits is None:
            return None
        for pc, store in exits:
            for loc, value in store.items():
                if loc[0] == "havoc" and loc[2] == "*elsewhere":
                    continue  # code run elsewhere on this storage (an entry point, a delegate): its own writes
                if loc[0] == "havoc" and loc[1] == THIS:
                    # A loop writing past what was followed: every entry of that variable (or of all of them, or
                    # every raw slot) may be anything.
                    if loc[2] in ("*", "raw") and pointer:
                        return None
                    for name in names if loc[2] == "*" else {loc[2]} & names:
                        out[(name, _ANYWHERE)] = None
                    continue
                if loc[0] == "raw":
                    if loc[1] != THIS:
                        continue
                    if not _settled(loc[2]) and _hashed(loc[2]) and not any(t[0] == "rawload" for t in loads):
                        continue  # a slot hashed from the arguments (keyed records): never a named variable's
                    if not _settled(loc[2]):
                        return None
                    slot, old = ("raw", loc[2]), mk("rawload", loc[1], loc[2])
                elif loc[0] == THIS:
                    slot, old = (loc[1], loc[2]), mk("load", loc[0], loc[1], loc[2])
                else:
                    continue
                leaves = _value_leaves(value, old)
                out.setdefault(slot, []).append((pc, frozenset(leaves) if leaves is not None else None, value))
    return out


def _by_reference(fn: Any) -> set[str]:
    """State variables ``fn`` hands to an internal function's ``storage`` parameter, which may write them through
    that pointer (MiniMe's ``updateValueAtNow(balances[_to], ...)``): Slither counts those writes against the
    pointer, not the variable."""
    from slither.core.variables.state_variable import StateVariable
    from slither.slithir.operations import InternalCall, LibraryCall

    out: set[str] = set()
    for node in fn.all_nodes():
        for ir in node.irs:
            if not isinstance(ir, (InternalCall, LibraryCall)):
                continue
            params = getattr(getattr(ir, "function", None), "parameters", None) or ()
            for param, arg in zip(params, ir.arguments):
                if getattr(param, "location", None) != "storage":
                    continue
                origin = getattr(arg, "points_to_origin", None) or arg
                if isinstance(origin, StateVariable):
                    out.add(origin.name)
    return out


def _stores(contract: Any, fn: Any, cache: dict) -> list | None:
    """(path condition, storage written) per way ``fn`` returns; ``None`` when it can't be lowered."""
    from .lower import State
    from .terms import TRUE, reintern, term_epoch

    if cache.get("epoch") != term_epoch():
        # Kept from an analysis since reset (another deployment of this code): rebuilt in today's table, or each
        # comparison with a term built now walks both whole.
        memo: dict[int, Any] = {}
        for k, v in cache.items():
            if k not in ("epoch", "delegating"):
                cache[k] = reintern(v, memo)
        cache["epoch"] = term_epoch()
    key = fn.canonical_name
    if key not in cache:
        try:
            args = {id(p): parameter(p, i) for i, p in enumerate(fn.parameters)}
            cache[key] = [(e.pc, e.store) for e in Lowerer(contract).run(fn, State(TRUE, args), 0)]
        except Exception as exc:  # a lowering failure leaves every condition adjustable
            if isinstance(exc, TimeoutError):
                raise
            cache[key] = None
    return cache[key]


def _delegates(pc: Term, store: dict) -> list[Term]:
    from .terms import subterms

    return [*subterms(pc, "delegate"), *(d for value in store.values() for d in subterms(value, "delegate"))]


def _own_code(delegate: Term) -> bool:
    """Whether a delegatecall runs this contract's own entry points (a ``multicall`` into ``address(this)``): writes
    they make are those entry points', each a writer in its own right."""
    target = delegate[1]
    while target[0] == "conv":
        target = target[2]
    return target == THIS


def _arbitrary(delegate: Term) -> bool:
    """Whether a delegatecall runs code the caller names: its target is made only of the call's arguments."""
    from .terms import subterms

    target = delegate[1]
    return bool(subterms(target, "arg")) and all(
        kind in ("arg", "conv") for kind in {t[0] for t in _all_subterms(target)}
    )


def _all_subterms(t: Any) -> list[Term]:
    """Every distinct term inside ``t``, ``t`` included, through operand sets and argument tuples; each shared
    subterm once (formulas are DAGs, exponential as trees)."""
    out: list[Term] = []
    seen: set[int] = set()
    stack = [t]
    while stack:
        node = stack.pop()
        if not isinstance(node, (tuple, frozenset)) or not node or id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, tuple) and isinstance(node[0], str):
            out.append(node)
            stack.extend(node[1:])
        else:
            stack.extend(node)
    return out


# The path a loop's writes past what was followed land at: any entry of the variable.
_ANYWHERE = (("*", None),)


def _values_at(writes: dict[tuple, list | None], load: Term) -> list | None:
    """The writes that may land at ``load`` (see ``_written_values``): those to a path that may be the same one (fields
    equal, keys equal unless either isn't a fixed value)."""
    if load[0] == "rawload":
        return writes.get(("raw", load[2]), [])
    out: list = []
    for (name, path), values in writes.items():
        if name != load[2]:
            continue
        if path == _ANYWHERE:
            return None  # a loop writes it past what was followed: anything
        if any(
            ka != kb or (ka == "f" and a != b) or (ka == "k" and _settled(a) and _settled(b) and a != b)
            for (ka, a), (kb, b) in zip(path, load[3])
        ):
            continue
        if values is None or len(path) != len(load[3]):
            # A write within what is read (an item pushed onto an array read whole) or around it (a whole struct
            # written over a field read): what it leaves there isn't any one of these values.
            return None
        out.extend(values)
    return out


def _reachable(world: World, load: Term, now: Any, writes: list) -> tuple[set, list] | None:
    """Constants ``load`` can come to hold from ``now``, and the writes of anything else that can run: a write counts
    once its condition can hold at a value already reachable, everything else in that condition left free (who calls,
    the arguments, other storage). So a consumed ``initializeV2`` (``version == 0``, writes 1) stays out of reach once
    ``version`` is 3. Once a write of anything else can run, the location may hold values no constant names, and
    every condition on it may hold."""
    reach: set = {now}
    open_writes: list = []
    for _ in range(_REACH_ROUNDS):
        grown = False
        anything = bool(open_writes)
        for condition, values, value in writes:
            if values is not None and values <= reach:
                continue
            if values is None and any(w[1] is value and w[0] is condition for w in open_writes):
                continue
            states = [UNK] if anything else sorted(reach, key=repr)
            if any(_may_hold(world, condition, load, state) for state in states):
                if values is None:
                    open_writes.append((condition, value))
                else:
                    reach |= values
                grown = True
        if not grown:
            return reach, open_writes
    return None


def _can_flip(world: World, atom: Term, load: Term, current: bool, condition: Term, value: Term) -> bool:
    """Whether a write of ``value`` (under ``condition``) can leave ``atom`` reading otherwise from any state where it
    still reads as now: an inductive check over the arguments, with the location, other storage, the caller and other
    contracts' answers all free values. ``threshold = _threshold`` under ``1 <= _threshold`` never makes
    ``threshold == 0`` true."""
    from .decide import solve
    from .terms import mk_not, replace_terms, stable

    before = mk("arg", "<location>", "uint256")
    pre = replace_terms(atom, {load: before})
    post = replace_terms(atom, {load: replace_terms(value, {load: before})})
    bounds = []
    if load[0] == "load" and load[3] and load[3][-1] == ("f", "length"):
        # A dynamic array's length stays below 2**64 (a ``push`` past it panics): one more never wraps to zero.
        from .terms import mk_cmp

        bounds.append(mk_cmp("lt", before, mk("const", 2**64, "uint256")))
    flip = [pre if current else mk_not(pre), mk_not(post) if current else post]
    if solve(mk_and([*bounds, *flip]), Evaluator(world, {"caller": FRESH, "signer": FRESH})) is None:
        return False  # no value it can hold leaves it otherwise, whatever the writer asks first
    goal = mk_and([replace_terms(condition, {load: before}), *bounds, *flip])
    # A field of an outside value (``config.epochsPerFrame`` of a call's struct) is an outside value too: free whole,
    # since a field of a free word can't be evaluated.
    environment = sorted(
        {
            t
            for t in _all_subterms(goal)
            if t[0] in _ENVIRONMENT or (t[0] == "op" and t[1] == "field" and t[2] and t[2][0][0] in _ENVIRONMENT)
        },
        key=stable,
    )
    outer = [t for t in environment if t[0] == "op"]
    inner = [t for t in environment if t[0] != "op"]
    goal = replace_terms(goal, {t: mk("arg", f"<field {i}>", "uint256") for i, t in enumerate(outer)})
    goal = replace_terms(goal, {t: mk("arg", f"<free {i}>", "uint256") for i, t in enumerate(inner)})
    return solve(goal, Evaluator(world, {"caller": FRESH, "signer": FRESH})) is not None


# What a latching check leaves free: everything a transaction doesn't fix through its own arguments.
_ENVIRONMENT = frozenset(
    (
        "load rawload caller origin signer call item ok caught time balance code codesize codehash immutable "
        "constant unknown opaque hash callvalue calldatasize delegate assumed"
    ).split()
)


def _may_hold(world: World, condition: Term, load: Term, value: Any) -> bool:
    free = frozenset(a for a in _atoms(condition) if load not in _loads(a))
    probe = Evaluator(world, {"caller": FRESH, "signer": FRESH}, {load: value}, when=free | {load})
    return probe.truth(condition) is not False


def _atoms(t: Term) -> frozenset:
    """The boolean conditions ``t`` combines with and/or/not/ite: once per shared node (a writer's merged guards)."""
    cached = t.__dict__.get("_atoms") if isinstance(t, Term) else None
    if cached is not None:
        return cached
    if t[0] in ("and", "or"):
        found = frozenset().union(*(_atoms(x) for x in t[1]))
    elif t[0] == "not":
        found = _atoms(t[1])
    elif t[0] == "ite":
        found = _atoms(t[1]) | _atoms(t[2]) | _atoms(t[3])
    else:
        found = frozenset() if t[0] == "const" else frozenset({t})
    if isinstance(t, Term):
        t.__dict__["_atoms"] = found
    return found


def _loads(t: Term) -> frozenset:
    """Every storage read inside ``t``. Built bottom-up and remembered on each interned term, so the many conditions
    sharing one large written value walk it once between them."""
    from .terms import Term as Interned
    from .terms import _children

    local: dict[int, frozenset] = {}
    stack: list[tuple[tuple, bool]] = [(t, False)]
    while stack:
        node, expanded = stack.pop()
        if id(node) in local:
            continue
        cached = node.__dict__.get("_loads") if isinstance(node, Interned) else None
        if cached is not None:
            local[id(node)] = cached
            continue
        children = [c for c in _children(node) if isinstance(c, tuple)]
        if not expanded:
            stack.append((node, True))
            stack.extend((c, False) for c in children if id(c) not in local)
            continue
        found = frozenset().union(*(local[id(c)] for c in children))
        if isinstance(node, Interned) and node and node[0] in ("load", "rawload"):
            found = found | {node}
        local[id(node)] = found
        if isinstance(node, Interned):
            node.__dict__["_loads"] = found
    return local[id(t)]


def _hashed(slot: Term) -> bool:
    """Whether a raw slot lies in hashed space: ``keccak256(...)``, plus an offset."""
    if slot[0] == "hash":
        return True
    return slot[0] == "op" and slot[1] == "add" and any(_hashed(a) for a in slot[2])


def _settled(t: Term) -> bool:
    """Whether ``t`` is a fixed value: constants and hashes of them (an unstructured-storage slot)."""
    if t[0] == "const":
        return True
    if t[0] in ("hash", "enc"):
        return all(_settled(a) for a in t[2])
    if t[0] == "op":
        return all(_settled(a) for a in t[2])
    return False


def _value_leaves(value: Term, unchanged: Term) -> set | None:
    """The constants a written value can be (through ``ite``), the location's own old value aside; ``None`` when
    it can be anything else. Compared by value: a contract's lowered writers are kept across analyses, whose terms are
    interned apart."""
    if value == unchanged:
        return set()
    if value[0] == "const":
        return {value[1]}
    if value[0] == "ite":
        a, b = _value_leaves(value[2], unchanged), _value_leaves(value[3], unchanged)
        return None if a is None or b is None else a | b
    return None


def _encoded_call(data: Term) -> tuple[int | None, list | None]:
    """(selector, arguments) of call data built by ``abi.encodeWithSelector`` / ``abi.encodeWithSignature``."""
    if data[0] != "enc" or not data[2]:
        return None, None
    head, rest = data[2][0], list(data[2][1:])
    if data[1] == "abi.encodeWithSelector" and head[0] == "const":
        value = int(head[1]) if isinstance(head[1], str) and head[1].isdigit() else head[1]  # ``I.f.selector``
        return (value % 2**32, rest) if isinstance(value, int) and not isinstance(value, bool) else (None, None)
    if data[1] == "abi.encodeWithSignature" and head[0] == "const" and isinstance(head[1], str):
        return int.from_bytes(keccak(text=head[1])[:4], "big"), rest
    return None, None


def _words(ret: tuple) -> tuple:
    """Return values as the caller decodes them: a struct the callee built (``S(a, b)``) is its fields, in order."""
    if len(ret) == 1 and isinstance(ret[0], tuple) and ret[0] and ret[0][0] == "struct":
        return tuple(ret[0][2])
    return ret


def _getter(contract: Any, call: Term) -> tuple[Term, tuple] | None:
    """A public state variable's getter (``mapping(address => bool) public isPauser``): its storage, keyed by the
    call's arguments. Slither has no body for it, only the interface's declaration."""
    from slither.core.solidity_types import ArrayType, MappingType

    name = call[2].split("(", 1)[0]
    var = next(
        (
            v
            for v in contract.state_variables
            if v.name == name and v.visibility == "public" and not v.is_constant and not v.is_immutable
        ),
        None,
    )
    if var is None:
        return None
    type_ = var.type
    for _ in call[3]:
        if not isinstance(type_, (MappingType, ArrayType)):
            return None
        type_ = type_.type_to if isinstance(type_, MappingType) else type_.type
    if isinstance(type_, (MappingType, ArrayType)) or _size_of(type_) is None:
        return None  # a struct or nested container: the getter returns parts of it
    return TRUE, (mk("load", call[1], var.name, tuple(("k", a) for a in call[3])),)


def _codeless(probe: Evaluator, call: Term) -> bool:
    """Whether a call's target has no code and never will: every call to it ends the same way, whatever anyone does
    here. Only for an address no code can come to (``_permanent``): any other address with no code now, a constant
    or an immutable included, may come to hold code (a contract created there later, at an address worked out in
    advance), so "no code there now" is how the condition reads now, never a latch."""
    if call[0] != "call" or not _permanent(probe, call[1]):
        return False
    target = probe.eval(call[1])
    if not isinstance(target, int) or isinstance(target, bool):
        return False
    return probe.world.chain.code(target % 2**160) == b""


_PRECOMPILES = range(1, 0x12)  # 0x01-0x11: addresses the protocol reserves, where no contract is ever created


def _permanent(probe: Evaluator, target: Term) -> bool:
    """Whether whether code sits at an address term can never change: this contract, or a precompile the code
    fixes (a constant, or a slot of this contract nothing can change: ``World.constant_load``), which no contract is
    ever created at."""
    if _strip(target) == THIS:
        return True
    if not _fixed_target(target, probe.world):
        return False
    value = probe.eval(target)
    return isinstance(value, int) and not isinstance(value, bool) and value % 2**160 in _PRECOMPILES


def _strip(term: Term) -> Term:
    while term[0] == "conv":
        term = term[2]
    return term


def _fixed_target(target: Term, world: World | None = None) -> bool:
    """Whether an address term is fixed by the code itself: constants, this contract, conversions of them, and a slot
    of this contract nothing can change (``World.constant_load``, which holds only where no delegatecall or proxy can
    write it). Not an immutable: whose it is (a callee's, at an address read from storage) and what it holds are set
    at deployment."""
    kind = target[0]
    if kind == "conv":
        return _fixed_target(target[2], world)
    if kind == "op":
        return all(_fixed_target(a, world) for a in target[2])
    if kind in ("load", "rawload") and world is not None:
        return world.constant_load(target)
    return kind in ("const", "this", "constant")


def _delegating(contract: Any, chain: Chain, address: int, code_of: Callable[[int], int] | None) -> bool:
    """Whether storage at ``address`` may be written by code other than ``contract``'s own entry points, so that no
    slot of it is constant however its own code reads: the contract makes a delegatecall (or callcode) of its own,
    low-level or in assembly (a library's internal functions are its own code); the address runs other code first (a
    proxy whose implementation ``code_of`` names, or whose deployed code delegates where the compiled contract
    doesn't, or is a different length from it; an EIP-7702 delegation); or that code can't be read."""
    from slither.core.cfg.node import NodeType

    for fn in contract.functions_and_modifiers:
        calls = [str(c) for c in [*fn.low_level_calls, *fn.solidity_calls]]
        if any("delegatecall" in c or "callcode" in c for c in calls) or any(
            n.type == NodeType.ASSEMBLY and re.search(r"\b(delegatecall|callcode)\s*\(", str(n.inline_asm or ""))
            for n in fn.nodes
        ):
            return True
    if code_of is not None and code_of(address) % 2**160 != address % 2**160:
        return True
    deployed = chain.code(address % 2**160)
    if not isinstance(deployed, bytes) or deployed[:3] == b"\xef\x01\x00":
        return True
    if not _delegate_ops(deployed):
        return False
    compiled = _runtime_code(contract)
    return not compiled or not _delegate_ops(compiled) or len(compiled) != len(deployed)


def _delegate_ops(code: bytes) -> bool:
    """Whether runtime code has a ``DELEGATECALL`` or ``CALLCODE`` opcode (push data and the metadata skipped)."""
    return bool(_opcodes(code) & {0xF2, 0xF4})


# Block fields that only grow; the others (base fee, coinbase, randomness) are anything in a later block.
_GROWING = frozenset({"timestamp", "number"})
_FIXED = frozenset({"chainid"})


def _time_flips(world: World, atom: Term, current: bool, probe: Evaluator) -> bool:
    """Whether a later block can read ``atom`` otherwise, everything else as it is now: ``block.timestamp <
    startTime`` comes true by waiting, ``block.timestamp > deadline`` never stops being."""
    from .decide import solve
    from .terms import mk_cmp, mk_not, replace_terms, subterms

    fields = {t for t in subterms(atom, "time") if t[1] not in _FIXED}
    if not fields:
        return False
    if any(t[1] not in _GROWING for t in fields):
        return True
    later = {t: mk("arg", f"<later {t[1]}>", "uint256") for t in fields}
    bounds = []
    for t, v in later.items():
        now = probe.eval(t)
        if not isinstance(now, int) or isinstance(now, bool):
            return True
        bounds.append(mk_cmp("ge", v, mk("const", now, "uint256")))
    moved = replace_terms(atom, later)
    goal = mk_and([*bounds, mk_not(moved) if current else moved])
    return solve(goal, probe) is not None


def latched_atoms(formula: Term, world: World, contract: Any) -> frozenset:
    """``when`` conditions this contract's code can never flip from how they read now: a consumed initializer's
    flag, a check of this contract's own code. Read as they are, not assumed adjustable."""
    from .terms import stable, subterms

    out: set[Term] = set()
    probe = Evaluator(world, {"caller": FRESH, "signer": FRESH})
    for atom in sorted(when_atoms(formula), key=stable):
        current = probe.truth(atom)
        if current is UNK:
            continue
        reads = [t for kind in ("call", "item", "ok", "caught") for t in subterms(atom, kind)]
        calls = {t if t[0] == "call" else t[1] for t in reads}
        if subterms(atom, "balance") or not all(_codeless(probe, call) for call in calls):
            continue  # another contract's answer, or ether: changeable from outside this code
        if not all(_permanent(probe, t[1]) for kind in ("codesize", "codehash", "code") for t in subterms(atom, kind)):
            continue  # code at an address code may yet be created at
        if _time_flips(world, atom, current, probe):
            continue  # a start not yet reached: time alone gets there
        loads = [*subterms(atom, "load"), *subterms(atom, "rawload")]
        if not loads:
            out.add(atom)  # nothing in it any transaction changes
            continue
        if any(t[1] != THIS for t in loads):
            continue
        writes = _written_values(contract, loads)
        if writes is None:
            continue
        options = []
        for t in loads:
            entries = _values_at(writes, t)
            now = probe.eval(t)
            if entries is None or now is UNK:
                break
            reached = _reachable(world, t, now, entries)
            if reached is None:
                break
            values, open_writes = reached
            if any(_can_flip(world, atom, t, current, condition, value) for condition, value in open_writes):
                break
            options.append([now, *sorted(values - {now}, key=repr)])
        else:
            if math.prod(len(o) for o in options) > _MAX_LATCH_STATES:
                continue
            fixed = all(
                Evaluator(world, probe.identity, dict(zip(loads, combo)), when=frozenset(loads)).truth(atom) == current
                for combo in itertools.product(*options)
            )
            if fixed:
                out.add(atom)
    return frozenset(out)


_ARRANGE_DEPTH = 2  # writers whose own guards may need arranging in turn (a redeem request needs shares first)
_ARRANGE_ATOMS = 48  # conditions looked at, per formula
ARRANGE_WORK = 60.0  # decision work the search for arrangeable entries may spend, apart from the decision's own


def arranged_within_budget(formula: Term, world: World, contract: Any) -> dict[Term, Term]:
    """``arranged_atoms`` on a budget of its own, so looking for them never starves the decision."""
    work, limit = world.work, world.work_limit
    world.work, world.work_limit = 0.0, ARRANGE_WORK
    try:
        return arranged_atoms(formula, world, contract)
    finally:
        world.work, world.work_limit = work, limit


def arranged_atoms(formula: Term, world: World, contract: Any, depth: int = 0) -> dict[Term, Term]:
    """Conditions on the caller's own entries in this contract's storage that a caller can bring about through code
    open to it. An entry is the caller's own when keyed by the caller, or by an address argument it may set to
    itself (``positions[onBehalfOf]``); it can be brought about when some entry point writes it under that writer's
    own caller, with something besides zero, past a guard every stranger passes: a position a ``supply`` opens, an
    allowance an ``approve`` sets, unlike a role only an admin grants or a ``renounceRole`` only takes away. A
    condition counts when every own entry it reads can be, and the caller enters it through those keys alone; each
    maps to where the entries are the caller's (those keys equal to it)."""
    from .decide import _atoms_of
    from .terms import IDENTITY_KINDS, contains, mk_cmp, stable, subterms

    out: dict[Term, Term] = {}
    memo: dict[tuple, bool] = world.__dict__.setdefault("_arrangeable", {})
    for atom in sorted(_atoms_of(formula), key=stable):
        if len(out) >= _ARRANGE_ATOMS or world.exhausted():
            break
        world.work += NODE_WORK
        held = _held_by_caller(atom)
        if held is not None:
            # ``owners[id] == msg.sender``: the caller's when an open entry point records its own caller there (a
            # mint, a withdrawal request) and the caller then names that entry.
            shape = ("held", held[2], tuple(k if k == "k" else (k, x) for k, x in held[3]))
            if shape not in memo:
                memo[shape] = False
                memo[shape] = _recordable(world, contract, held, depth)
            if memo[shape]:
                out[atom] = TRUE
            continue
        held_calls = sorted(
            {c for c in subterms(atom, "call") if c[4] and any(contains(a, IDENTITY_KINDS) for a in c[3])}, key=stable
        )
        if held_calls and not _identity_outside(atom, frozenset(held_calls)):
            # ``token.balanceOfAt(msg.sender, snapshot) > 0``: a holding another contract keeps for the caller,
            # which open code there credits to any address (a transfer in). Anyone can come to hold it: a
            # requirement on what the caller holds, not on who it is.
            if all(world.credited(c) for c in held_calls):
                out[atom] = TRUE
                world.requirements[atom] = held_calls
            continue
        loads = sorted(
            {t for t in subterms(atom, "load") if t[1] == THIS and any(_owner_key(k, x) for k, x in t[3])}, key=stable
        )
        if not loads or _identity_outside(atom, frozenset(loads)):
            continue
        if not any(contains(t, IDENTITY_KINDS) or contains(t, frozenset({"arg"})) for t in loads):
            continue
        hashed = _compared_with_hash(atom, loads)
        ok = True
        for load in loads:
            shape = _load_shape(load, load in hashed)
            if shape not in memo:
                memo[shape] = False  # while being asked: a writer needing this very entry first doesn't count
                memo[shape] = _arrangeable(world, contract, load, depth, valued=load in hashed)
                if not memo[shape] and load not in hashed and _creditable(world, contract, load):
                    # Nothing the caller does fills it, but holders can move it to anyone: a balance the caller
                    # is given.
                    memo[shape] = True
                    world.__dict__.setdefault("_credited", {})[shape] = True
            if not memo[shape]:
                ok = False
                break
        if ok:
            own = {mk_cmp("eq", x, CALLER) for t in loads for k, x in t[3] if _owner_key(k, x)}
            out[atom] = mk_and(sorted(own, key=stable))
            given = [t for t in loads if world.__dict__.get("_credited", {}).get(_load_shape(t, t in hashed))]
            if given:
                world.requirements[atom] = given
    return out


def _load_shape(load: Term, hashed: bool) -> tuple:
    return (load[2], tuple(k if k == "k" else (k, x) for k, x in load[3]), hashed)


def _compared_with_hash(atom: Term, loads: list[Term]) -> set[Term]:
    """The entries ``atom`` asks to equal a hash (``clear`` wanting a payload's hash stored for it)."""
    if atom[0] != "cmp" or atom[1] != "eq":
        return set()
    return {mine for mine, other in ((atom[2], atom[3]), (atom[3], atom[2])) if mine in loads and other[0] == "hash"}


def _held_by_caller(atom: Term) -> Term | None:
    """The entry ``atom`` compares the caller with (``owners[id] == msg.sender``), when nothing else in it names the
    caller and the caller picks the entry: some key is an argument, the rest constants. A lone variable
    (``owner == msg.sender``) is never one: writing it takes it from whoever holds it."""
    from .terms import IDENTITY_KINDS, contains

    if atom[0] != "cmp" or atom[1] != "eq":
        return None
    sides = [atom[2], atom[3]]
    for i, side in enumerate(sides):
        while side[0] == "conv":
            side = side[2]
        sides[i] = side
    for mine, other in ((sides[0], sides[1]), (sides[1], sides[0])):
        if mine == CALLER and other[0] == "load" and other[1] == THIS and not contains(other, IDENTITY_KINDS):
            keys = [x for k, x in other[3] if k == "k"]
            if keys and all(x[0] in ("arg", "const") for x in keys) and any(x[0] == "arg" for x in keys):
                return other
    return None


def _recordable(world: World, contract: Any, load: Term, depth: int) -> bool:
    """Whether some entry point stores its own caller (or an address it is passed) at ``load``'s entry, past a guard
    a stranger passes: an id the caller is then free to name."""
    from .decide import _is_identity
    from .terms import mk_cmp

    writes = _written_values(contract, [load])
    stranger = {"caller": FRESH, "signer": FRESH}
    unsure = False
    for (name, path), entries in (writes or {}).items():
        # A write of the whole struct (``queue[id] = Request(...)``) counts for each field read from it.
        rest = load[3][len(path) :]
        if name != load[2] or len(path) > len(load[3]) or not entries or any(k != "f" for k, _ in rest):
            continue
        if any(ka != kb or (ka == "f" and a != b) for (ka, a), (kb, b) in zip(path, load[3])):
            continue
        if any(
            k == "k" and read[0] == "const" and written != read and written[0] != "arg"
            for (k, written), (_, read) in zip(path, load[3])
        ):
            continue
        for condition, _, whole in entries:
            for _, field in rest:
                whole = _field(whole, field)
            for when, value in _branches(whole):
                if _is_identity(value):
                    bound: list[Term] = [when]
                elif value[0] == "arg" and value[2] == "address":
                    bound = [when, mk_cmp("eq", value, CALLER)]
                else:
                    continue
                passed = _recordable_under(world, contract, mk_and([condition, *bound]), depth, stranger)
                if passed is True:
                    return True
                unsure = unsure or passed is not False
    if unsure:
        # A guard the node's answers left open, and none that passed: whether a stranger can record itself there
        # is unknown.
        world.arrange_unknown = True
    return False


def _field(value: Term, name: str) -> Term:
    """Field ``name`` of a written struct, through the ``ite``s choosing between structs; ``FALSE`` when unknown."""
    from .terms import mk_ite

    if value[0] == "struct" and name in value[1]:
        return value[2][value[1].index(name)]
    if value[0] == "ite":
        return mk_ite(value[1], _field(value[2], name), _field(value[3], name))
    return FALSE


def _branches(value: Term, depth: int = 4) -> list[tuple[Term, Term]]:
    """(condition, value) for each value an ``ite`` chain can leave (``_owner == 0 ? msg.sender : _owner``)."""
    from .terms import mk_not

    while value[0] == "conv":
        value = value[2]
    if value[0] != "ite" or depth == 0:
        return [(TRUE, value)]
    return [
        *((mk_and([value[1], c]), v) for c, v in _branches(value[2], depth - 1)),
        *((mk_and([mk_not(value[1]), c]), v) for c, v in _branches(value[3], depth - 1)),
    ]


def _recordable_under(world: World, contract: Any, guard: Term, depth: int, stranger: dict) -> Any:
    """Whether a stranger gets past ``guard``, its own arrangeable entries arranged first: True, False or UNK."""
    from .decide import _outcome

    saved = world.arranged
    if depth < _ARRANGE_DEPTH:
        world.arranged = {**saved, **arranged_atoms(guard, world, contract, depth + 1)}
    try:
        return _outcome(guard, world, stranger, set(), relaxed="arguments")
    finally:
        world.arranged = saved


def _identity_outside(term: Term, inside: frozenset) -> bool:
    """Whether the caller or signer appears in ``term`` other than within the terms ``inside``."""
    from .terms import IDENTITY_KINDS, _children, contains

    seen: set[int] = set()
    stack = [term]
    while stack:
        t = stack.pop()
        if id(t) in seen or t in inside or not contains(t, IDENTITY_KINDS):
            continue
        seen.add(id(t))
        if isinstance(t, tuple) and t and isinstance(t[0], str) and t[0] in IDENTITY_KINDS:
            return True
        stack.extend(c for c in _children(t) if isinstance(c, tuple))
    return False


def _owner_key(kind: str, key: Term) -> bool:
    """A key naming an account the caller may be: the caller itself, or an address argument."""
    if kind != "k":
        return False
    while key[0] == "conv":
        key = key[2]
    return key[0] in IDENTITY_KINDS or (key[0] == "arg" and key[2] == "address")


def _arrangeable(world: World, contract: Any, load: Term, depth: int, valued: bool = False) -> bool:
    """Whether some entry point writes ``load``'s entry under its own caller's key, with something besides zero,
    past a guard a stranger passes (business conditions left free). ``valued``: a value the caller supplies, not only
    constants (a constant never equals the hash the entry is compared with)."""
    from .decide import _is_identity, _outcome
    from .terms import mk_cmp

    writes = _written_values(contract, [load])
    stranger = {"caller": FRESH, "signer": FRESH}
    unsure = False
    for (name, path), entries in (writes or {}).items():
        if name != load[2] or len(path) != len(load[3]) or not entries:
            continue
        if any(ka != kb or (ka == "f" and a != b) for (ka, a), (kb, b) in zip(path, load[3])):
            continue
        bound = []
        for (kind, written), (_, read) in zip(path, load[3]):
            if kind != "k":
                continue
            if _owner_key(kind, read):
                if _is_identity(written):
                    continue
                if not _owner_key(kind, written):
                    break
                bound.append(mk_cmp("eq", written, CALLER))
            elif not (written == read or written[0] == "arg"):
                break
        else:
            for condition, leaves, _ in entries:
                if leaves is not None and not any(v not in (0, False) for v in leaves):
                    continue  # writes only zero: takes away, never grants
                if valued and leaves is not None:
                    continue  # writes only constants where a hash is wanted
                guard = mk_and([condition, *bound])
                saved = world.arranged
                if depth < _ARRANGE_DEPTH:
                    world.arranged = {**saved, **arranged_atoms(guard, world, contract, depth + 1)}
                try:
                    passed = _outcome(guard, world, stranger, set(), relaxed="arguments")
                    if passed is True:
                        return True
                    unsure = unsure or passed is not False
                finally:
                    world.arranged = saved
    if unsure:
        # A guard the node's answers left open, and none that passed: whether a stranger can bring this about is
        # unknown.
        world.arrange_unknown = True
    return False


def _creditable(world: World, contract: Any, load: Term) -> bool:
    """Whether some entry point moves a nonzero value into ``load``'s entry at an address its caller names, other
    than its own (``balances[_to] += amount``), past a guard a stranger passes once holding that same entry itself
    (a transfer needs the sender's balance): an entry anyone can be given by whoever holds it."""
    from .decide import _is_identity, _outcome
    from .terms import mk_cmp, mk_not

    writes = _written_values(contract, [load])
    stranger = {"caller": FRESH, "signer": FRESH}
    memo: dict = world.__dict__.setdefault("_creditable", {})
    owners = [i for i, (k, x) in enumerate(load[3]) if _owner_key(k, x)]
    # Where the same call takes from its caller's own entry (``balances[msg.sender] -= amount``): a move, as opposed to
    # an entry only someone with standing hands out (a role ``grantRole`` gives without giving up its own).
    debits = {
        condition
        for (name, path), entries in (writes or {}).items()
        if name == load[2]
        and len(path) == len(load[3])
        and all(ka == kb and (ka != "f" or a == b) for (ka, a), (kb, b) in zip(path, load[3]))
        and all(_is_identity(path[i][1]) for i in owners)
        for condition, _, _ in entries or ()
    }
    for (name, path), entries in (writes or {}).items():
        if name != load[2] or len(path) != len(load[3]) or not entries:
            continue
        if any(ka != kb or (ka == "f" and a != b) for (ka, a), (kb, b) in zip(path, load[3])):
            continue
        if (name, path) in memo:
            if memo[(name, path)]:
                return True
            continue
        memo[(name, path)] = False
        bound = []
        for (kind, written), (_, read) in zip(path, load[3]):
            if kind != "k" or not _owner_key(kind, read):
                continue
            if _is_identity(written) or not _owner_key(kind, written):
                break  # the writer's own entry, or one it doesn't let its caller name
            bound.append(mk_not(mk_cmp("eq", written, CALLER)))
        else:
            if not bound:
                continue
            for condition, leaves, _ in entries:
                if leaves is not None and not any(v not in (0, False) for v in leaves):
                    continue  # writes only zero: takes away, never gives
                if condition not in debits:
                    continue  # gives without taking from its caller: no move between holders
                guard = mk_and([condition, *bound])
                # The sender's own entries of the same lookup, of the same shape, are what it moves: held, for this
                # question.
                own = {
                    atom: TRUE
                    for atom in _guard_atoms(guard)
                    if any(
                        t[1] == THIS
                        and t[2] == name
                        and len(t[3]) == len(load[3])
                        and all(ka == kb and (ka != "f" or a == b) for (ka, a), (kb, b) in zip(t[3], load[3]))
                        and all(_is_identity(t[3][i][1]) for i in owners)
                        for t in _loads_in(atom)
                    )
                }
                saved = world.arranged
                world.arranged = {**saved, **own}
                try:
                    if _outcome(guard, world, stranger, set(), relaxed="arguments") is True:
                        memo[(name, path)] = True
                        return True
                finally:
                    world.arranged = saved
    return False


def _guard_atoms(term: Term) -> list[Term]:
    from .decide import _atoms_of
    from .terms import stable

    return sorted(_atoms_of(term), key=stable)


def _loads_in(term: Term) -> list[Term]:
    from .terms import subterms

    return list(subterms(term, "load"))


_PRIOR_WRITERS = 6  # entry points tried as the stranger's own first call, per function


def after_own_call(formula: Term, world: World, contract: Any) -> tuple | None:
    """A call a stranger makes first, to an entry point here that writes the entries this function reads under the
    caller's key, after which it gets through (``assignDelegate`` before ``unassignDelegate``): that function's
    signature, the arguments of that call and of this one; ``None`` when none does. Each write is worked out on
    the chain as it stands and read back in its place, so the pair is a run of two calls, not a rule."""
    from .decide import _argument_values, _outcome
    from .terms import contains, subterms

    names = {
        t[2]
        for t in subterms(formula, "load")
        if t[1] == THIS and isinstance(t[2], str) and any(k == "k" and contains(x, IDENTITY_KINDS) for k, x in t[3])
    }
    # An entry compared with a hash of what the caller sends (``stored[me] == keccak256(message)``) passes only
    # with a preimage of what is stored; whatever the stranger writes there itself, it has none.
    hashed = {
        t[2]
        for atom in subterms(formula, "cmp")
        if atom[1] == "eq"
        for mine, other in ((atom[2], atom[3]), (atom[3], atom[2]))
        if _unconverted(other)[0] == "hash"
        for t in subterms(mine, "load")
    }
    names -= hashed
    if not names:
        return None
    writers = [
        f
        for f in contract.functions_entry_points
        if not (f.view or f.pure or f.is_constructor)
        and names & ({v.name for v in f.all_state_variables_written()} | _by_reference(f))
    ]
    cache = contract.__dict__.setdefault("_psat_stores", {})
    # What the formula reads here: a write anywhere else can't change whether it passes, unless something reads
    # storage the formula doesn't name (a call, a raw slot).
    read = (
        None
        if subterms(formula, "call") or subterms(formula, "rawload")
        else names | {t[2] for t in subterms(formula, "load") if t[1] == THIS}
    )
    # A step left unanswered (a read the node failed): whether some first call lets a stranger through is unknown,
    # which a stranger failing now can't then settle (``World.arrange_unknown``).
    unsure = False
    for fn in writers[:_PRIOR_WRITERS]:
        exits = _stores(contract, fn, cache)
        for pc, store in exits or ():
            if world.exhausted():
                world.arrange_unknown = True
                return None
            if not any(loc[0] == THIS and loc[1] in names for loc in store):
                continue
            if any(loc[0] == THIS and loc[1] in hashed for loc in store):
                continue
            found: dict = {}
            first = _outcome(pc, world, {"caller": FRESH, "signer": FRESH}, set(), fixed={}, witness=found)
            if first is UNK:
                # Unsettled for the parts no identity reaches (an index below a length read under a key the stranger
                # picks): the arguments the parts it does reach take (``account == msg.sender``) are what decide
                # where its writes land; a stranger those parts refuse can't make the call at all.
                own = mk_and([c for c in conjuncts(pc) if contains(c, IDENTITY_KINDS)])
                found = {}
                if _outcome(own, world, {"caller": FRESH, "signer": FRESH}, set(), fixed={}, witness=found) is False:
                    continue
            if first is False:
                continue
            saved = world.overlay
            witness: dict = {}
            try:
                # Each stranger alone: its own call first, on the chain as it stands, then this one. Whether the first
                # call runs may be unknown (a read failed): a stranger still failing after it shows it doesn't help.
                for index, who in enumerate((FRESH, *_OTHER_STRANGERS)):
                    world.overlay = saved
                    identity = {"caller": who, "signer": who}
                    probe = Evaluator(world, identity, found)
                    made = probe.truth(pc)
                    changed = {
                        loc: v
                        for loc, v in store.items()
                        if not _clears_own(probe, loc, v) and (read is None or loc[0] != THIS or loc[1] in read)
                    }
                    writes = _concrete_writes(probe, changed, world.this) if made is not False else None
                    if not writes:
                        # Where it writes unknown (``None``): no proof it doesn't help.
                        unsure = unsure or (made is not False and writes is None)
                        break
                    world.overlay = {**saved, **writes}
                    then = _outcome(formula, world, identity, set(), fixed={}, witness=witness if not index else None)
                    # A word written unknown reads as unknown: failing with it is failing whatever it holds.
                    if then is not True or made is not True:
                        unsure = unsure or then is not False
                        break
                else:
                    return fn.solidity_signature, _argument_values(found), _argument_values(witness)
            finally:
                world.overlay = saved
    if unsure:
        world.arrange_unknown = True
    return None


def _clears_own(probe: Evaluator, loc: tuple, value: Term) -> bool:
    """A write of zero to an entry keyed by the stranger itself (``renounceRole``): its entries already read zero,
    wherever the other keys put it."""
    from .decide import _STRANGERS

    if loc[0] != THIS or not any(kind == "k" and probe.eval(step) in _STRANGERS for kind, step in loc[2]):
        return False
    word = probe.eval(value)
    return isinstance(word, int) and word == 0


def _unconverted(t: Term) -> Term:
    while t[0] == "conv":
        t = t[2]
    return t


def _concrete_writes(probe: Evaluator, store: dict, this: int) -> dict | None:
    """The storage words a call's writes leave, (address, slot) -> word, each worked out from the state before it;
    a word it writes something unknown to is UNK. ``None`` when where it writes can't be worked out."""
    from .decide import _size

    out: dict = {}
    for loc, value in store.items():
        if loc[0] == "raw":
            slot, word = probe.eval(loc[2]), probe.eval(value)
            if probe.eval(loc[1]) != this or not isinstance(slot, int) or isinstance(slot, bool):
                return None
            out[(this, slot % 2**256)] = int(word) % 2**256 if isinstance(word, int) else UNK
            continue
        if loc[0] != THIS:
            continue  # an event, a call out, transient storage: nothing left in this contract's slots
        for path, part in _leaves(loc[2], value):
            cell = probe.storage_cell(mk("load", THIS, loc[1], path))
            if cell is None:
                return None
            address, slot, offset, type_ = cell
            word = probe.eval(part)
            size = _size(type_)
            base = out.get((address, slot), probe.word(address, slot))
            if (
                not isinstance(word, int)
                or not isinstance(base, int)
                or isinstance(base, bool)
                or str(type_) in ("bytes", "string")
                or (size is None and offset)
            ):
                out[(address, slot)] = UNK
                continue
            size = size or 32
            mask = (2 ** (8 * size) - 1) << (8 * offset)
            out[(address, slot)] = (base & ~mask) | ((int(word) % 2 ** (8 * size)) << (8 * offset))
    return out


def _leaves(path: tuple, value: Term) -> list[tuple[tuple, Term]]:
    """A write of a whole struct as the writes of its fields (through the ``ite``s choosing between structs)."""
    from .terms import subterms

    names: list[str] = []
    for t in [value, *subterms(value, "struct")]:
        if t[0] == "struct":
            names = list(t[1])
            break
    if not names:
        return [(path, value)]
    return [leaf for name in names for leaf in _leaves((*path, ("f", name)), _field(value, name))]


def _declared_events(contract: Any) -> list:
    """Events ``contract``'s code may emit: its own, and those its libraries and files declare (Lido's
    ``Proposers.ProposerRegistered``, emitted from the library's code inside the contract)."""
    unit = contract.compilation_unit
    return [
        *contract.events,
        *(e for c in unit.contracts if c is not contract for e in c.events),
        *getattr(unit, "events_top_level", []),
    ]


def _same_lookup(current: Any, earlier: Any, var: Any) -> Any:
    """How ``earlier`` code names the storage ``current`` calls ``var``: the state variable at the same slot and
    offset with the same type (renamed or not), or, for a member of a namespaced struct, the same name where
    ``earlier`` lays that struct out alike up to it. ``None`` when it can't be matched."""
    memo = current.__dict__.setdefault("_psat_same_lookup", {})
    key = (earlier, repr(var))
    if key not in memo:
        memo[key] = _matched_lookup(current, earlier, var)
    return memo[key]


def _matched_lookup(current: Any, earlier: Any, var: Any) -> Any:
    from .decide import _slots, locate

    if isinstance(var, str) and any(v.name == var for v in current.state_variables_ordered):
        here = locate(current, var, ())
        if here is None:
            return None
        for v in earlier.state_variables_ordered:
            if v.is_constant or getattr(v, "is_immutable", False):
                continue
            there = locate(earlier, v.name, ())
            if there is None:
                return None  # a layout this can't place: whether it reaches the slot is unknown
            if there[:2] == here[:2]:
                return v.name if _type_shape(there[2]) == _type_shape(here[2]) else None
            if there[0] <= here[0] < there[0] + max(_slots(there[2]), 1):
                return None  # a struct or fixed array of ``earlier``'s spanning the slot: another shape there
        # Nothing of ``earlier``'s at that slot: its code wrote no entry there by name (a raw write that might is
        # what ``logged`` still checks, asked about a name nothing has).
        return _NOTHING_THERE

    def structures(contract: Any) -> dict:
        unit = contract.compilation_unit
        found = [*contract.structures, *(s for c in unit.contracts for s in c.structures)]
        found += list(getattr(unit, "structures_top_level", []))
        return {s.canonical_name: s for s in found}

    def names(structure: Any) -> list:
        return [e.name for e in structure.elems_ordered]

    mine = {name: s for name, s in structures(current).items() if var in names(s)}
    if not mine:
        return None
    theirs = structures(earlier)
    if not any(name in theirs for name in mine) and not any(var in names(s) for s in theirs.values()):
        # ``earlier`` declares no such namespace (its data kept as plain variables, moved over by a later upgrade):
        # it wrote nothing there by name, and a raw write is what ``logged`` still checks.
        return _NOTHING_THERE
    for name, structure in mine.items():
        other = theirs.get(name)
        at = names(structure).index(var) + 1
        if other is None or names(other)[:at] != names(structure)[:at]:
            return None
        # Members appended after it move nothing: the layout up to it, and its own shape, decide where it is.
        if [_type_shape(e.type) for e in other.elems_ordered[:at]] != [
            _type_shape(e.type) for e in structure.elems_ordered[:at]
        ]:
            return None
    return var


_NOTHING_THERE = "<nothing there>"


def _type_shape(type_: Any, depth: int = 0) -> str:
    """A type as its storage layout depends on it: a struct by its members in order, through mappings and arrays
    (a field added between implementations moves the ones after it)."""
    from slither.core.declarations import Structure
    from slither.core.solidity_types import ArrayType, MappingType, UserDefinedType

    if depth > 6:
        return "?"
    if isinstance(type_, MappingType):
        return f"mapping({type_.type_from}=>{_type_shape(type_.type_to, depth + 1)})"
    if isinstance(type_, ArrayType):
        return f"{_type_shape(type_.type, depth + 1)}[{type_.length or ''}]"
    if isinstance(type_, UserDefinedType) and isinstance(type_.type, Structure):
        members = ",".join(f"{e.name}:{_type_shape(e.type, depth + 1)}" for e in type_.type.elems_ordered)
        return "{" + members + "}"
    return str(type_)


def _merged(a: Any, b: Any) -> Any:
    """Two implementations' answers as one: events or field paths united; writer specs united, ``None`` where both
    log one event with its keys or value at different places."""
    if isinstance(a, (set, frozenset)):
        return frozenset(a) | frozenset(b)
    if a and isinstance(a[0], dict) or b and isinstance(b[0], dict):
        by: dict[Any, dict] = {}
        for spec in [*a, *b]:
            seen = by.setdefault(spec["event_signature"] or hex(spec["topic0"]), spec)
            placed = {k: v for k, v in spec.items() if k not in ("mapping_name", "member_path")}
            if {k: v for k, v in seen.items() if k not in ("mapping_name", "member_path")} != placed:
                return None
        return list(by.values())
    return sorted({*map(tuple, a), *map(tuple, b)}, key=repr)


def _places(kind: str, place: Any) -> list[int]:
    """The argument positions a key's place reads (``logged.keyed_by``): one, none for a constant, or a hashed
    key's parts'."""
    if kind == "at":
        return [place]
    if kind == "parts":
        return [p for k, p in place if k == "at"]
    return []


def _read_place(kind: str, place: Any, args: dict[int, int]) -> Any:
    """A key read back from a log's arguments: its word, or a hashed key's parts as a tuple of words."""
    if kind == "is":
        return place % 2**256 if isinstance(place, int) else place
    if kind == "at":
        return None if args.get(place) is None else args[place] % 2**256
    parts = tuple(_read_place(k, p, args) for k, p in place)
    return None if any(p is None for p in parts) else parts


def _spec_name(var: Any) -> Any:
    """A lookup as writer events name it: a slot-rooted mapping (``_storageRoles()[role]``) by its type."""
    if isinstance(var, tuple) and len(var) == 3 and var[0] == "slot" and str(var[2]).startswith("mapping("):
        return str(var[2])
    return var


_ORIGIN = frozenset({"origin"})
_CHOSEN = frozenset({"arg", "len", "elem", "callvalue", "calldatasize"})
_ORIGIN_OP = 0x32
_CALL_OPS = frozenset({0xF1, 0xF2, 0xF4, 0xFA})  # CALL, CALLCODE, DELEGATECALL, STATICCALL
# The keys a compiler's metadata map holds, as CBOR text strings: only a trailer naming one is skipped.
_METADATA_KEYS = (b"\x64ipfs", b"\x65bzzr0", b"\x65bzzr1", b"\x64solc")


def _runtime_reach(code: bytes) -> str | None:
    """``origin`` when runtime code has an ``ORIGIN`` opcode, ``unfollowed`` when it has a call opcode (what it calls
    may read the origin), else ``None``."""
    seen = _opcodes(code)
    return "origin" if _ORIGIN_OP in seen else "unfollowed" if seen & _CALL_OPS else None


def _opcodes(code: bytes) -> set[int]:
    """The opcodes runtime code holds: a walk over them, skipping push data and the trailing metadata."""
    if len(code) >= 2:
        size = int.from_bytes(code[-2:], "big")
        meta = code[-size - 2 : -2] if size + 2 <= len(code) else b""
        if meta and 0xA0 <= meta[0] <= 0xBF and any(key in meta for key in _METADATA_KEYS):
            code = code[: -size - 2]  # the compiler's CBOR metadata: data, never run
    seen: set[int] = set()
    i = 0
    while i < len(code):
        op = code[i]
        seen.add(op)
        i += 1 + (op - 0x5F if 0x60 <= op <= 0x7F else 0)
    return seen


def _hidden_calls(term: Term) -> bool:
    """Whether ``term`` holds a call's outcome its lowering doesn't show: a low-level call's (``assumed``, its return
    data ``opaque``), an action's, or a delegatecall's."""
    if subterms(term, "assumed") or subterms(term, "delegate"):
        return True
    if any(str(o[1]).startswith(("returndata", "dynamic:")) for o in subterms(term, "opaque")):
        return True
    return any(not c[4] for c in subterms(term, "call"))


def _unconditional(formula: Term, call: Term) -> bool:
    """Whether every use of ``call``'s value in ``formula`` is reached on every path that passes: inside a top-level
    conjunct under no ``ite``, ``or`` or ``and`` (whether it returns, ``ok``/``caught``, is exact anywhere)."""

    def plain(t: Any) -> bool:
        if isinstance(t, frozenset):
            return all(plain(x) for x in t)
        if not isinstance(t, tuple) or not t or t == call or not contains_term(t, call):
            return True
        if isinstance(t[0], str) and t[0] in ("ok", "caught") and t[1] == call:
            return True
        if isinstance(t[0], str) and t[0] in ("ite", "or", "and"):
            return False  # short-circuits: below the top level, a conjunction may stop before the call
        return all(plain(x) for x in (t[1:] if isinstance(t[0], str) else t))

    return all(plain(c) for c in (formula[1] if formula[0] == "and" else (formula,)))


# Chain reads one function's decision may send; past it, reads answer unknown (sound, never wrong).
READS_PER_FUNCTION = 2000
# Where a cap on all the reads a chain may send is supplied (``function_verdict(read_cap=...)``, else the
# ``PSAT_LOGIC_READ_CAP`` environment variable), the most of what is left of it one function may send: one function
# never spends a whole run's reads.
READ_CAP_SHARE = 0.25
# Of those, the most a function may send confirming passes only a callee's code showed (``decide.confirming``): about
# one per holder such a check lets through, each its own call.
CONFIRM_READS = 300


def _inlined_verdict(
    formula: Term,
    stripped: Term,
    world: World,
    cover: Callable[[Term], Any],
    signatures: list[str],
) -> Verdict:
    """The verdict where ``bind_callers`` put a callee's code (one reading ``tx.origin``, whose call the chain would
    answer with this contract as the origin) in place of its call in ``formula``. That code is trusted for nothing:
    the verdict is decided on ``stripped``, each such call an unknown no caller is marked alike for, so no refusal
    and no list rests on it. Where that leaves the answer open or the list incomplete, the inlined formula only
    proposes, and the chain confirms by running the whole call (``decide.runs``): a stranger's pass with the
    arguments found makes it open; each holder it lists whose own call goes through is listed, the list never
    complete on its word. Any it proposes that the chain doesn't confirm is left undecided, and the verdict names
    ``inlined_callee:<signature>``."""
    kept = {k: world.__dict__.get(k) for k in ("arranged", "dumped", "arrange_unknown")}
    base = decide(stripped, world, cover(stripped))
    if base.openness == "open" or base.complete:
        return base
    world.__dict__.update(kept)
    proposed = decide(formula, world, cover(formula))
    gaps = tuple(f"inlined_callee:{signature}" for signature in signatures)
    witness = proposed.witnesses.get(FRESH)
    if proposed.openness == "open" and proposed.allowed == "now" and witness is not None:
        if runs(world, FRESH, witness) is True and strangers_run(formula, world, witness):
            return proposed  # every stranger's own call goes through on the chain
    offered = sorted((proposed.principals | set(proposed.conditions)) - base.principals)
    confirmed = {}
    for who in offered[:_EXECUTED_CANDIDATES]:
        if runs(world, who, proposed.witnesses.get(who, {})) is True:
            confirmed[who] = proposed.witnesses.get(who, {})
    principals = base.principals | frozenset(confirmed)
    unconfirmed = (frozenset(offered) | proposed.signers) - principals - base.signers
    return replace(
        base,
        principals=principals,
        undecided=(base.undecided | unconfirmed) - principals,
        witnesses={**base.witnesses, **confirmed},
        conditions={k: v for k, v in base.conditions.items() if k not in confirmed},
        gaps=base.gaps + gaps + proposed.gaps,
    )


def function_reads(chain: Chain, read_cap: int | None = None) -> int:
    """The reads one function's decision may send: ``READS_PER_FUNCTION``, or less where a cap on the chain's reads
    in all is supplied (``read_cap``, else ``PSAT_LOGIC_READ_CAP``): ``READ_CAP_SHARE`` of what is left of it."""
    if read_cap is None:
        supplied = os.environ.get("PSAT_LOGIC_READ_CAP", "").strip()
        read_cap = int(supplied) if supplied.isdigit() else None
    if read_cap is None:
        return READS_PER_FUNCTION
    return min(READS_PER_FUNCTION, int(max(0, read_cap - chain.sent) * READ_CAP_SHARE))


def function_verdict(
    contract: Any,
    function: Any,
    address: int,
    chain: Chain,
    contracts: dict[int, Any],
    values: dict[str, Any] | None = None,
    code_of: Callable[[int], int] | None = None,
    read_cap: int | None = None,
) -> tuple[Verdict, Term]:
    """``contracts`` maps addresses to Slither contracts the formula may read or call (``address`` included), the
    code that runs there; ``code_of`` maps an address to the one holding that code (a proxy's implementation);
    ``read_cap``, the most reads ``chain`` may send in all (counted by ``chain.sent``), of which this function takes
    at most ``READ_CAP_SHARE`` of what is left."""
    failed_at = chain.failed  # failed reads before this function: see ``World.failed_at``
    chain.limit = chain.sent + function_reads(chain, read_cap)
    chain.scan_left = chain.history_seconds = LOG_SECONDS
    chain.scan_total = LOG_TOTAL_SECONDS
    lowerer = Lowerer(contract)
    formula = lowerer.success(function)
    selector = int.from_bytes(keccak(text=function.solidity_signature)[:4], "big")
    world = World(chain, address, selector, contracts, dict(values or {}), _address_literals(contract))
    world.effective = lowerer.effective
    world.confirm_left = CONFIRM_READS
    world.written = lowerer.written
    world.parameters = tuple(parameter(p, i) for i, p in enumerate(function.parameters))
    if code_of is not None:
        world.code_of = code_of
    relations: dict[int, set] = {}
    lowered: dict[Term, tuple[Term, tuple] | None] = {}

    def address_of(term: Term) -> Any:
        # A read deferred to a batch (``Chain.gather``) answers unknown until fetched: an unknown address is asked
        # again only once the chain has answered something new. Remembered in the world, which a block that must
        # leave no trace (``decide.detached``) puts back as it was.
        addresses = world.__dict__.setdefault("_addresses", {})
        known = len(chain._memo)
        held = addresses.get(term)
        if held is None or (held[0] is UNK and held[1] != known):
            held = (Evaluator(world, {"caller": FRESH, "signer": FRESH}).eval(term), known)
            addresses[term] = held
        return held[0]

    def contract_at(term: Term) -> tuple[int, Any] | None:
        target = address_of(term)
        if not isinstance(target, int) or isinstance(target, bool) or target not in contracts:
            return None
        return target, contracts[target]

    specs: dict[int, list] = {}

    def writer_specs(target: int) -> list:
        if target not in specs:
            from services.static.contract_analysis_pipeline.mapping_events import discover_mapping_writer_events

            specs[target] = discover_mapping_writer_events(contracts[target], per_writer=True, fields=True)
        return specs[target]

    histories: dict[int, list | None] = {}

    def versions(target: int) -> list | None:
        """The code of every implementation ``target`` has run, the one running now last (``versions.py``); ``None``
        when that history is unknown, or an implementation in it has no code to read."""
        if target not in histories:
            from .versions import implementations

            running = code_of(target) if code_of is not None else target
            found = implementations(chain, target, running)
            codes: list | None = None
            if found is not None:
                codes = [contracts[target] if impl == running % 2**160 else contracts.get(impl) for impl in found]
                if any(code is None for code in codes):
                    codes = None
            histories[target] = codes
        return histories[target]

    def every(target: int, ask: Callable, var: Any, *args: Any, raw: bool = False, **kwargs: Any) -> Any:
        """``ask(code, var, ...)`` for the code of every implementation ``target`` has run, each answer merged: a
        write an earlier one made stays in storage, so a lookup is logged only if every one of them logged it.
        ``var`` is named as each implementation names the same storage (``_same_lookup``); ``None`` when one
        doesn't answer, names it differently in a way that can't be matched, or the history is unknown."""
        codes = versions(target)
        if codes is None:
            return None
        out: Any = None
        for code in codes:
            name = var if raw or code is codes[-1] else _same_lookup(codes[-1], code, var)
            if name is None:
                return None
            answer = ask(code, name, *args, **kwargs)
            if answer is None:
                return None
            out = answer if out is None else _merged(out, answer)
            if out is None:
                return None
        return out

    def valued_specs(target: int, var: Any, fields: tuple) -> list:
        """The writer events that name both the key and the value left at ``var``'s ``fields``: as the static
        pipeline found them, or else as the lowering shows them (writes made in a library on a storage pointer)."""
        found = [
            spec
            for spec in (writer_specs(target) if versions(target) == [contracts[target]] else ())
            if spec["mapping_name"] == var
            and spec.get("value_position") is not None
            and tuple(spec.get("member_path") or ()) == tuple(fields)
        ]
        return found or every(target, written_by, var, tuple(fields)) or []

    def running_specs(target: int, var: Any, fields: tuple) -> list:
        """``valued_specs`` from the running code alone: events that name a key and its value as it writes them."""
        found = [
            spec
            for spec in writer_specs(target)
            if spec["mapping_name"] == var
            and spec.get("value_position") is not None
            and tuple(spec.get("member_path") or ()) == tuple(fields)
        ]
        return found or written_by(contracts[target], var, tuple(fields)) or []

    def complete(contract_term: Term, var: Any, keys: int, fields: tuple) -> bool:
        var = _spec_name(var)
        found = contract_at(contract_term)
        if found is None:
            return False
        target, target_contract = found
        if target not in relations:
            from services.static.contract_analysis_pipeline.mapping_events import complete_writer_relations

            relations[target] = complete_writer_relations(target_contract, writer_specs(target))
        if (var, keys, tuple(fields)) in relations[target] and versions(target) == [target_contract]:
            return True  # the static pipeline's relations know only the code running now
        return every(target, logged, var, keys, tuple(fields), False) is not None

    def keyed(contract_term: Term, var: Any, keys: int, fields: tuple) -> bool:
        """``complete``, or complete but for the constructor's writes, whose keys the creating transaction's trace
        accounts for: those keys are then candidates (``World.created``). For listing holders only: what values
        the constructor left isn't in the events (``World.complete`` stays strict for ``identity == m[k]``)."""
        if complete(contract_term, var, keys, fields):
            return True
        found = contract_at(contract_term)
        if found is None or chain.debug is None:
            return False
        target, target_contract = found
        if every(target, logged, _spec_name(var), keys, tuple(fields), False, constructors=False) is None:
            return False
        made = creation_keys(chain, target, target_contract)
        if made is None:
            return False
        world.created.setdefault(target, set()).update(made)
        return True

    raw_events: dict[int, set] = {}

    def listed(contract_term: Term, var: Any, fields: tuple, slot: Term | None) -> bool:
        """Whether a lookup keyed by a hash of the identity is listed whole by its events: a mapping read at
        ``hash(identity, ...)`` (``var``), or a raw slot hashed from it (``slot``); see ``logged``."""
        found = contract_at(contract_term)
        if found is None:
            return False
        target, target_contract = found
        if slot is not None:
            events = every(target, logged_raw, slot, raw=True)
            if events is not None:
                raw_events.setdefault(target, set()).update(events)
            return events is not None
        return every(target, logged, _spec_name(var), 1, tuple(fields), True) is not None

    def entries(
        contract_term: Term, var: Any, keys: int, fields: tuple, whole: bool = True
    ) -> list[tuple[int, ...]] | None:
        """Every key tuple an entry of ``var`` (read under ``keys`` keys, at ``fields``) was ever set at, read off
        the events that log each write's keys, when every such write does and that history was read whole: a list
        of all that can be set there, some since cleared. ``None`` otherwise. ``whole=False``: the tuples the
        running code's logged writes name, as far as the history was read: keys to try, never all of them."""
        var = _spec_name(var)
        found = contract_at(contract_term)
        if found is None:
            return None
        target, target_contract = found
        specs = every(target, keyed_by, var, keys, tuple(fields)) if whole else None
        if not whole:
            specs = keyed_by(target_contract, var, keys, tuple(fields), whole=False)
        made: frozenset = frozenset()
        if specs is None and chain.debug is not None and whole:
            # Every write logged but the constructor's, whose keys the creating transaction accounts for: under more
            # than one key, each such address may be at any of them, the others unread.
            specs = every(target, keyed_by, var, keys, tuple(fields), constructors=False)
            created = creation_keys(chain, target, target_contract) if specs is not None else None
            if created is None or versions(target) != [target_contract]:
                return None
            made = frozenset(created)
        if specs is None:
            return None
        by_topic = {
            spec.get("topic0") or int.from_bytes(keccak(text=spec["event_signature"]), "big"): spec for spec in specs
        }
        topics = frozenset("0x" + format(t, "064x") for t in by_topic)
        logs = chain.logs(target, topics)
        if whole and chain.cut(target, topics):
            return None
        out: set[tuple[int, ...]] = set()
        for log_topics, data in logs:
            spec = by_topic.get(log_topics[0]) if log_topics else None
            if spec is None:
                continue
            at = [p for kind, place in spec["keys"] for p in _places(kind, place)]
            args = _event_args({**spec, "value_position": max(at, default=0)}, log_topics, data)
            row = [_read_place(kind, place, args) for kind, place in spec["keys"]]
            if any(word is None for word in row):
                if not whole:
                    continue
                return None  # a log shorter than its declaration: not read as listed
            out.add(tuple(row))
        out |= {tuple(k if i == at else ANY_KEY for i in range(keys)) for k in made for at in range(keys)}
        return sorted(out, key=lambda row: [(w is ANY_KEY, 0 if w is ANY_KEY else w) for w in row])

    def _topics(target: int, events: Any) -> dict[int, list[tuple[str, bool]]]:
        """topic0 -> (ABI type, indexed) parameters of the events ``logged`` named: declared ones by name and
        arity; one written in assembly by its topic, each further topic read as an address that may be a key."""
        out: dict[int, list[tuple[str, bool]]] = {}
        by = set()
        for event in events or ():
            if event[0] == "topic0":
                out[event[1]] = [("address", True)] * event[2]
            else:
                by.add(event)
        for e in _declared_events(contracts[target]):
            if (e.name, len(e.elems)) in by:
                out[int.from_bytes(keccak(text=e.full_name), "big")] = [(str(x.type), bool(x.indexed)) for x in e.elems]
        return out

    def logging_events(target: int, var: Any) -> dict[int, list[tuple[str, bool]]]:
        if var == RAW_SLOT:
            return _topics(target, raw_events.get(target))
        out: dict[int, list[tuple[str, bool]]] = {}
        for hashed in (False, True):
            # The constructor's writes aside too: what ``keyed`` relies on to list holders with the creating trace.
            events = every(target, logged, var, 1, (), hashed)
            if events is None:
                events = every(target, logged, var, 1, (), hashed, constructors=False)
            if events is None:
                # A member of it on its own: a struct's lookup beside a list whose indexes no event names.
                for fields in every(target, members, var) or ():
                    out.update(_topics(target, every(target, logged, var, 1, fields, hashed)))
            out.update(_topics(target, events))
        return out

    def writer_events(target: int, var: Any) -> dict[int, list[tuple[str, bool]]]:
        var = _spec_name(var)
        if target not in contracts:
            return {}
        if var != RAW_SLOT and every(target, logged, var, 1, (), False) is not None:
            return dict(logging_events(target, var))  # see ``writer_topics``
        signatures = {spec["event_signature"] for spec in writer_specs(target) if spec["mapping_name"] == var}
        signatures |= _writer_events(contracts[target], var) if var != RAW_SLOT else set()
        out: dict[int, list[tuple[str, bool]]] = dict(logging_events(target, var))
        for event in contracts[target].events:
            if event.full_name in signatures:
                params = [(str(e.type), bool(e.indexed)) for e in event.elems]
                out[int.from_bytes(keccak(text=event.full_name), "big")] = params
        return out

    def values_of(contract_term: Term, var: Any, keys: int, fields: tuple) -> frozenset | None:
        """Every value ``var``'s ``fields`` have held at any key: zero, and each value recorded by the events every
        write to them emits (``RoleAdminChanged``'s new admin); ``None`` unless those events are complete and read."""
        var = _spec_name(var)
        found = contract_at(contract_term)
        if found is None or not complete(contract_term, var, keys, fields):
            return None
        target, _ = found
        by_topic = {
            int.from_bytes(keccak(text=spec["event_signature"]), "big"): spec
            for spec in valued_specs(target, var, fields)
        }
        if not by_topic:
            return None
        topics = frozenset("0x" + format(topic, "064x") for topic in by_topic)
        logs = chain.logs(target, topics)
        if chain.cut(target, topics):
            return None
        out = {0}
        for log_topics, words in logs:
            spec = by_topic.get(log_topics[0]) if log_topics else None
            if spec is None:
                continue
            written = _event_args(spec, log_topics, words).get(spec["value_position"])
            if written is None:
                return None
            out.add(written)
        return frozenset(out) if len(out) <= 32 else None

    def writer_topics(target: int, var: Any) -> frozenset[str]:
        """Events that can name a key of ``var``: those matched to its writes, and every event a function writing it
        emits (``setup`` writes Safe owners in a loop and emits them all in one ``SafeSetup``)."""
        var = _spec_name(var)
        if target not in contracts:
            return frozenset()
        if var != RAW_SLOT and every(target, logged, var, 1, (), False) is not None:
            # The lowering shows which events name the keys of every write that can set an entry: those alone, not
            # every event a writing function emits (each deposit on a hub that also writes its spokes).
            return frozenset("0x" + format(t, "064x") for t in logging_events(target, var))
        matched = {spec["event_signature"] for spec in writer_specs(target) if spec["mapping_name"] == var}
        matched |= _writer_events(contracts[target], var) if var != RAW_SLOT else set()
        topics = {"0x" + keccak(text=sig).hex() for sig in matched}
        return frozenset(topics | {"0x" + format(t, "064x") for t in logging_events(target, var)})

    def callee(call: Term, address: int | None = None) -> tuple[Term, tuple] | None:
        """``call``'s callee lowered in this call's terms; at ``address`` when the asker knows where the target
        is under its own arguments, else where it is whatever they are."""
        if address is None:
            address = address_of(call[1])
            if address is UNK:
                return None  # not read yet: asked again once it is
        if not isinstance(address, int) or isinstance(address, bool):
            return None
        key = (call, address % 2**160)
        if key not in lowered:
            found = (address % 2**160, contracts[address % 2**160]) if address % 2**160 in contracts else None
            lowered[key] = None
            if found is not None:
                target = found[1].get_function_from_signature(call[2])
                if target is not None and target.entry_point is not None:
                    # Inside the callee, ``msg.sender`` is whoever makes the call (this contract, or the callee that
                    # asks it in turn), ``this`` is the callee, and the frame is its own (see ``Lowerer.called``).
                    sender = call[5] if len(call) > 5 else THIS
                    pc, ret = Lowerer(found[1], sender=sender, this=call[1]).called(target, list(call[3]), call[4])
                    # What it declares it returns: solc 0.4 lets ``return f()`` stand in a function returning nothing.
                    lowered[key] = (pc, _words(ret) if target.returns else ())
                else:
                    lowered[key] = _getter(found[1], call)
                    if (
                        lowered[key] is None
                        and target is None
                        and not any(f.is_fallback for f in found[1].functions_entry_points)
                    ):
                        lowered[key] = (FALSE, ())  # no such function and no fallback: the call reverts
        return lowered[key]

    def asker_free(call: Term) -> bool:
        """Whether what a call made by followed code answers can't depend on who makes it: the callee's own code,
        lowered with a stand-in for its ``msg.sender``, never shows the stand-in, reads nothing it couldn't express,
        and neither it nor anything it asks reads ``tx.origin`` (``caller_bound``). Then this contract asking gets the
        same answer as the callee that makes the call would."""
        address = address_of(call[1])
        if len(call) <= 5 or not isinstance(address, int) or isinstance(address, bool):
            return len(call) <= 5
        asked = world.__dict__.setdefault("_asker_free", {})
        key = (call, address % 2**160)
        if key not in asked:
            asked[key] = False
            contract_ = contracts.get(address % 2**160)
            target = contract_.get_function_from_signature(call[2]) if contract_ is not None else None
            if target is not None and target.entry_point is not None and caller_bound(call) is None:
                stand_in = mk("arg", "frame:asker", "address")
                pc, ret = Lowerer(contract_, sender=stand_in, this=call[1]).called(target, list(call[3]), call[4])
                parts = [p for p in (pc, *ret) if isinstance(p, Term)]
                asked[key] = not any(
                    stand_in in subterms(p, "arg") or contains(p, frozenset({"unknown", "opaque", "delegate"}))
                    for p in parts
                )
            elif contract_ is not None and (target is None or target.entry_point is None):
                asked[key] = _getter(contract_, call) is not None  # a public variable's getter reads only storage
        return asked[key]

    def lower_call(call: Term) -> Term | None:
        found = callee(call)
        if found is None:
            return None
        pc, ret = found
        return mk_and([pc, ret[0]]) if ret else pc

    def delegate(term: Term) -> Term:
        """A delegatecall's success: the delegate's code on this contract's storage, for the same caller. Without
        data of its own (``delegate(target)``) it runs this very call, as a proxy forwards it; with data
        (``delegate(target, data)``), the function that data's selector names, on its arguments."""
        target_term = term[1]
        if _arbitrary(term):
            return mk("assumed", "delegatecall")  # code the caller names: they pick some that succeeds
        found = contract_at(target_term)
        if found is None:
            return unknown("delegate_unanalysed")
        implementation = found[1]
        called, args = (selector, None) if len(term) == 2 else _encoded_call(term[2])
        if called is None:
            return unknown("delegate_data")
        fn = next(
            (
                f
                for f in implementation.functions_entry_points
                if not f.is_fallback
                and not f.is_receive
                and f.solidity_signature
                and int.from_bytes(keccak(text=f.solidity_signature)[:4], "big") == called
            ),
            None,
        )
        fn = fn or next((f for f in implementation.functions_entry_points if f.is_fallback), None)
        if fn is None:
            return FALSE  # no such function and no fallback: the delegate reverts
        lowerer = Lowerer(implementation, code=target_term)
        if args is None:
            return lowerer.success(fn)
        if fn.is_fallback or len(args) != len(fn.parameters):
            return unknown("delegate_data")
        return lowerer.returns(fn, args)[0]

    replayed: dict[tuple, dict[int, int]] = {}
    guessed: dict[tuple, dict[int, int]] = {}

    def inverse(target: int, var: str, fields: tuple, value: int, proof: bool = True) -> set[int] | None:
        """Keys whose latest written value at ``var`` (under ``fields``) is ``value``, replaying the writer events
        once per mapping; ``None`` when that history was cut or unread, so whose value it is isn't known.
        ``proof=False``: keys to try only, each checked on the chain: the running code's events, however the
        earlier implementations logged, and a history read partial for what it holds."""
        if target not in contracts:
            return set()
        if not proof:
            if (target, var, fields) not in guessed:
                guessed[(target, var, fields)] = _latest_written(target, var, fields, proof=False) or {}
            return {
                key for key, written in guessed[(target, var, fields)].items() if written % 2**160 == value % 2**160
            }
        if (target, var, fields) not in replayed:
            replayed[(target, var, fields)] = _latest_written(target, var, fields)
        latest = replayed[(target, var, fields)]
        if latest is None:
            return None
        return {key for key, written in latest.items() if written % 2**160 == value % 2**160}

    def latest(target: int, var: Any, fields: tuple) -> dict[int, int] | None:
        """Key -> its latest written value, when every write to ``var``'s ``fields`` is logged with both."""
        if target not in contracts or every(target, logged, _spec_name(var), 1, tuple(fields), False, True) is None:
            return None
        if (target, var, fields) not in replayed:
            replayed[(target, var, fields)] = _latest_written(target, var, fields)
        return replayed[(target, var, fields)]

    def _latest_written(target: int, var: str, fields: tuple, proof: bool = True) -> dict[int, int] | None:
        specs = (
            valued_specs(target, _spec_name(var), fields) if proof else running_specs(target, _spec_name(var), fields)
        )
        by_topic = {int.from_bytes(keccak(text=spec["event_signature"]), "big"): spec for spec in specs}
        topics = frozenset("0x" + format(t, "064x") for t in by_topic)
        latest: dict[int, int] = {}
        logs = chain.logs(target, topics)
        if proof and chain.cut(target, topics):
            return None
        for log_topics, data in logs:
            spec = by_topic.get(log_topics[0]) if log_topics else None
            if spec is None:
                continue
            args = _event_args(spec, log_topics, data)
            key, written = (
                args.get(spec["key_positions_by_index"].get(0, spec["key_position"])),
                args.get(spec["value_position"]),
            )
            if key is not None and written is not None:
                latest[key] = written
        return latest

    def immutable(at: int, name: str) -> Any:
        if at not in contracts:
            return UNK
        offsets = immutable_offsets(contracts[at]).get(name)
        if not offsets:
            return UNK
        code = chain.code(code_of(at) if code_of is not None else at)
        if not isinstance(code, bytes):
            return UNK
        value = immutable_value(code, offsets)
        return UNK if value is None else value

    opened: dict[tuple, bool] = {}

    def action_open(call: Term, refused: Term) -> bool | frozenset:
        """Whether the callee refuses only on the caller's own entries in its storage, keyed by the caller handed to
        it, that open code there lets anyone bring about (an allowance ``approve`` sets, a balance a transfer moves
        in), asked in the callee's own world. A failure on anything else is no action the caller arranges. When only
        some are (a token's balances, not its blacklist): those entries, as ``refused`` reads them."""
        from .terms import contains as _contains
        from .terms import stable, subterms

        found = contract_at(call[1])
        if found is None:
            return True
        target, callee_contract = found
        read = {
            mk("load", THIS, t[2], t[3]): t
            for t in subterms(refused, "load")
            if t[1] == call[1] and any(k == "k" and _contains(x, IDENTITY_KINDS) for k, x in t[3])
        }
        own = sorted(read, key=stable)
        if not own:
            return False
        key = (target, tuple(own))
        if key not in opened:
            there = World(chain, target, 0, contracts, {}, _address_literals(callee_contract))
            there.immutable = immutable
            there.callee = callee
            there.work, there.work_limit = 0.0, ARRANGE_WORK
            there.deadline = world.deadline
            given_here, brought = [], []
            for load in own:
                if _arrangeable(there, callee_contract, load, 0):
                    brought.append(load)
                elif _creditable(there, callee_contract, load):
                    given_here.append(load)  # a balance holders move to anyone: the caller has to hold it
                    brought.append(load)
            opened[key] = True if len(brought) == len(own) else frozenset(brought) if brought else False
            if opened[key] is not False and given_here:
                world.held_actions[key] = (target, sorted({str(load[2]) for load in given_here}))
        if opened[key] is not False and key in world.held_actions:
            world.requirements[call] = world.held_actions[key]
        found_here = opened[key]
        return frozenset(read[load] for load in found_here) if isinstance(found_here, frozenset) else found_here

    def valued(contract_term: Term, var: Any, keys: int, fields: tuple) -> bool:
        """Whether every value ``var``'s entries have held is in its events: read back, or proven logged."""
        if values_of(contract_term, var, keys, fields) is not None:
            return True
        found = contract_at(contract_term)
        return (
            found is not None and every(found[0], logged, _spec_name(var), keys, tuple(fields), False, True) is not None
        )

    def settled(term: Term) -> bool:
        answer = Evaluator(world, {"caller": FRESH, "signer": FRESH}).truth(term)
        return answer is True or answer is False

    given: dict[Term, bool] = {}

    def credited(call: Term) -> bool:
        """Whether ``call``'s result, for the identity handed it, reads only that identity's entries in the
        callee's storage, each of which open code there moves to any address (``balanceOfAt(holder, block)`` over
        balances a transfer credits)."""
        from .terms import contains as _contains
        from .terms import stable, subterms

        if call in given:
            return given[call]
        given[call] = False
        found = contract_at(call[1])
        lowered = callee(call)
        if found is None or lowered is None:
            return False
        target, callee_contract = found
        pc, ret = lowered
        whole = mk_and([pc, *ret])
        own = sorted(
            {
                t
                for t in subterms(whole, "load")
                if t[1] == call[1] and any(k == "k" and _contains(x, IDENTITY_KINDS) for k, x in t[3])
            },
            key=stable,
        )
        # Asked onward (MiniMe's ``parentToken.balanceOfAt(owner, ...)`` for history before its own): a call into
        # no code is never made, one into a holding of the same kind holds the same.
        onward = {
            c
            for c in subterms(whole, "call")
            if c != call
            and any(_contains(a, IDENTITY_KINDS) for a in c[3])
            and (_codeless_address(address_of(c[1])) or credited(c))
        }
        if not own or _identity_outside(whole, frozenset(own) | onward):
            return False
        there = World(chain, target, 0, contracts, {}, _address_literals(callee_contract))
        there.immutable = immutable
        there.callee = callee
        there.work, there.work_limit = 0.0, ARRANGE_WORK
        there.deadline = world.deadline
        given[call] = all(_creditable(there, callee_contract, mk("load", THIS, t[2], t[3])) for t in own)
        return given[call]

    def _codeless_address(address: Any) -> bool:
        return address == 0 or (
            isinstance(address, int) and not isinstance(address, bool) and chain.code(address % 2**160) == b""
        )

    def caller_bound(call: Term, depth: int = 0) -> str | None:
        """Why a view call handed nothing of the caller may still answer otherwise for another caller, else
        ``None``. Inside any callee ``tx.origin`` is the caller's, and the chain answers such a call with this
        contract as the origin, so its answer is trusted only where no code it may run reads the origin: ``origin``
        when its followed code does, ``nested`` when a callee it asks does; ``unfollowed`` when code not followed has
        a call opcode (it may reach one) or can't be read, or the callees go deeper than followed (``origin`` when it
        has an ``ORIGIN`` opcode); ``read_failed:call_target`` when where it goes can't be read. A followed callee's
        lowering never shows on its own that the origin goes unread (a mis-lowered read of it is no ``origin`` term):
        that takes its runtime code too, deployed and compiled, holding no ``ORIGIN`` opcode (``hidden`` when one
        does, ``unfollowed`` when that code can't be read)."""
        bound = world.__dict__.setdefault("_caller_bound", {})
        key = (call, depth)
        if key in bound:
            return bound[key]
        bound[key] = "unfollowed"  # while being worked out: a callee reached again inside itself
        if contains(call[1], _CHOSEN):
            # Code the caller picks: asked about per guess, as any call to an address the caller names.
            bound[key] = None
            return None
        address = address_of(call[1])
        if not isinstance(address, int) or isinstance(address, bool):
            why: str | None = "read_failed:call_target"
        else:
            lowered = callee(call)
            if lowered is None:
                code = chain.code(address % 2**160)
                why = "unfollowed" if not isinstance(code, bytes) else _runtime_reach(code)
            else:
                parts = [p for p in (lowered[0], *lowered[1]) if isinstance(p, Term)]
                why = "origin" if any(contains(p, _ORIGIN) for p in parts) else None
                if why is None:
                    reach = _code_reach(address % 2**160)
                    if reach == "origin":
                        why = "hidden"  # its code reads the origin where its lowering shows none
                    elif reach == "unreadable" or any(_hidden_calls(p) for p in parts):
                        # Code it runs that its lowering doesn't show (a low-level call, an action), or code that
                        # can't be read: the origin may be read behind it.
                        why = "unfollowed"
                for inner in sorted({c for p in parts for c in subterms(p, "call") if c[4]}, key=stable):
                    if why is not None:
                        break
                    if depth + 1 >= IDENTITY_DEPTH:
                        why = "unfollowed"
                    else:
                        deeper = caller_bound(inner, depth + 1)
                        why = "nested" if deeper in ("origin", "nested") else deeper
        bound[key] = why
        return why

    def _code_reach(address: int) -> str:
        """``origin`` when code that runs at ``address`` (as deployed there, at the address whose code it runs, or
        as the followed contract was compiled) has an ``ORIGIN`` opcode, ``unreadable`` when the deployed code can't
        be read, else ``none``."""
        held = world.__dict__.setdefault("_code_reach", {})
        if address not in held:
            codes = [chain.code(address)]
            running = code_of(address) % 2**160 if code_of is not None else address
            if running != address:
                codes.append(chain.code(running))
            if not all(isinstance(code, bytes) for code in codes):
                held[address] = "unreadable"
                return held[address]
            if address in contracts:
                codes.append(_runtime_code(contracts[address]))
            held[address] = "origin" if any(_ORIGIN_OP in _opcodes(code) for code in codes) else "none"
        return held[address]

    inlined: list[str] = []  # signatures of the calls ``bind_callers`` put its callee's code in place of

    def bind_callers(term: Term, top: bool, inline: bool = True) -> Term:
        """``term`` with each view call ``caller_bound`` names kept from being read as the same for everyone. One
        whose followed code reads ``tx.origin`` (itself, or a callee it asks) is inlined in the formula itself
        (``top``): asked whether it returns (``ok``, ``caught``), its success condition stands in; used for its
        value, its return value does, and its success condition joins the formula, which holds only where every use
        of it is reached unconditionally (in a top-level conjunct, under no ``ite`` or ``or``). The calls that brings
        in are asked about in turn, a few rounds deep. Every other such call becomes an unknown no caller is marked
        alike for, named ``origin:``, ``unfollowed:`` or ``read_failed:call_target:`` and the signature. A call
        handed the caller is asked about the origin (and where it goes) only: whatever else its callee does, the
        caller it is handed already keeps it out of what every caller faces alike. ``inline=False``: every such call
        an unknown, nothing inlined (the formula no callee's code is trusted in, see ``_inlined_verdict``)."""
        for round_ in range(IDENTITY_DEPTH + 1):
            changed = False
            for call in sorted({c for c in subterms(term, "call") if c[4]}, key=stable):
                if not contains_term(term, call):
                    continue  # inlined already, inside another's place
                why = caller_bound(call)
                if why is None or (
                    tainted(call) and why not in ("origin", "nested", "hidden", "read_failed:call_target")
                ):
                    continue
                lowered = callee(call) if why in ("origin", "nested") else None
                uses = [x for x in subterms(term, "item") if x[1] == call]
                bare = call in subterms(replace_terms(term, {x: TRUE for x in uses}, keep_subjects=True), "call")
                inlining = inline and lowered is not None and top and round_ < IDENTITY_DEPTH
                if inlining and (not (uses or bare) or _unconditional(term, call)):
                    inlined.append(call[2])
                    pc, ret = lowered
                    mapping: dict[Term, Term] = {}
                    for x in subterms(term, "ok"):
                        if x[1] == call:
                            mapping[x] = pc
                    for x in subterms(term, "caught"):
                        if x[1] == call:
                            mapping[x] = mk_not(pc)
                    for x in uses:
                        mapping[x] = ret[x[2]] if x[2] < len(ret) else unknown(f"origin:{call[2]}")
                    if bare:
                        mapping[call] = ret[0] if ret else unknown(f"origin:{call[2]}")
                    term = replace_terms(term, mapping)
                    if uses or bare:
                        term = mk_and([term, pc])
                else:
                    label = "origin" if why in ("origin", "nested", "hidden") else why
                    term = replace_terms(term, {call: unknown(f"{label}:{call[2]}")})
                changed = True
            if not changed:
                break
        return term

    world.failed_at = failed_at
    delegated = substitute(formula, "delegate", delegate)
    formula = assume_conjuncts(bind_callers(delegated, True))
    # With a callee's code inlined, the same formula with each such call an unknown instead: what decides.
    stripped = assume_conjuncts(bind_callers(delegated, True, inline=False)) if inlined else None
    effective = substitute(world.effective, "delegate", delegate)
    world.effective = assume_conjuncts(bind_callers(effective, False))
    world.callee = callee
    world.asker_free = asker_free
    world.caller_bound = caller_bound
    world.action_open = action_open
    world.credited = credited
    world.writer_topics = writer_topics
    world.writer_events = writer_events
    world.complete = complete
    world.values_of = values_of
    world.entries = entries
    world.latest = latest
    world.inverse = inverse
    world.immutable = immutable

    def constant_load(load: Term) -> bool:
        """Whether this contract's slot ``load`` reads can never hold anything but what it holds now: no entry point
        writes it, or none can leave it holding anything else from here (``_reachable``, as latching asks); and no
        code but the contract's own entry points can write it (``_delegating``: no delegatecall of its own, no proxy
        in front of it)."""
        if load[1] != THIS:
            return False
        memo = world.__dict__.setdefault("_constant_loads", {})
        if "delegating" not in memo:
            memo["delegating"] = _delegating(contracts.get(address, contract), chain, address, code_of)
        if memo["delegating"]:
            return False
        if load not in memo:
            writes = _written_values(contracts.get(address, contract), [load])
            entries = _values_at(writes, load) if writes is not None else None
            if entries is None:
                memo[load] = False
            elif not entries:
                memo[load] = True
            else:
                now = Evaluator(world, {"caller": FRESH, "signer": FRESH}).eval(load)
                reached = None if now is UNK else _reachable(world, load, now, entries)
                if now is UNK or reached is None:
                    return False  # unread, or not settled: asked again
                memo[load] = reached[0] == {now} and not reached[1]
        return memo[load]

    world.constant_load = constant_load
    world.latched = latched_atoms(formula, world, contracts.get(address, contract))
    world.cover = lambda term: coverage(term, keyed, lower_call, listed, settled, valued)
    world.arrange = lambda term: arranged_within_budget(term, world, contracts.get(address, contract))
    world.prior = lambda term: after_own_call(term, world, contracts.get(address, contract))
    world.scope = classify(lowerer.exits, lowerer.lost, function, contract_facts(contract))
    if stripped is None:
        verdict = decide(formula, world, coverage(formula, keyed, lower_call, listed, settled, valued))
    else:
        world.latched |= latched_atoms(stripped, world, contracts.get(address, contract))
        verdict = _inlined_verdict(
            formula,
            stripped,
            world,
            lambda term: coverage(term, keyed, lower_call, listed, settled, valued),
            sorted(set(inlined)),
        )
    gate = verdict.gate or (gate_of(formula) if world.scope.kind == "self" else ())
    return replace(verdict, scope=world.scope.kind, scope_writes=world.scope.writes, gate=gate), formula
