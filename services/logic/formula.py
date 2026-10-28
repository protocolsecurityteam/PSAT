"""Lower code into full success/effect predicates and guarded state updates."""

from __future__ import annotations

from typing import Any

from eth_utils.crypto import keccak

from .immutables import immutable_offsets, immutable_value
from .lower import Lowerer, parameter, unwritten
from .model import BudgetExceeded, Effect, Formula, Limits, Reads, Transition, Update
from .solver import Translation, number
from .terms import (
    CALLDATA,
    THIS,
    TRUE,
    Term,
    const,
    contains,
    mk,
    mk_and,
    mk_cmp,
    mk_not,
    mk_or,
    replace_terms,
    returned_part,
    unknown,
)


class Linker:
    """Follow verified callees in their actual call frames; never ask eth_call for a verdict."""

    def __init__(self, reads: Reads, contracts: Any, address: int, limits: Limits, code_of=None, bindings=None):
        self.reads, self.contracts, self.address, self.limits = reads, contracts, address, limits
        self.code_of = code_of or (lambda at: at)
        self.bindings = bindings
        self.cache: dict[tuple, Any] = {}
        self.active: set[Term] = set()
        self.expanded: dict[tuple[Term, int], Term] = {}

    def concrete(self, t: Term) -> int | None:
        # Linking may read a fixed address, but must not enumerate a caller/argument-keyed
        # mapping to discover possible call targets. Enumeration belongs to expansion.
        bound = replace_terms(
            t,
            {
                key: const(value, key[2] if key[0] == "arg" else "uint256")
                for key, value in (self.bindings or {}).items()
                if isinstance(value, (int, bool, str, bytes))
            },
        )
        if contains(
            bound,
            frozenset(
                {
                    "caller",
                    "origin",
                    "signer",
                    "arg",
                    "callvalue",
                    "calldatasize",
                    "unknown",
                    "opaque",
                    "call",
                    "delegate",
                }
            ),
        ):
            return None
        evaluator = Translation(self.reads, self.contracts, self.address, limits=self.limits, bindings=self.bindings)
        v = evaluator.translate(t)
        if any(i.kind == "budget" for i in evaluator.issues):
            raise BudgetExceeded("callee resolution reads")
        return None if evaluator.issues else number(v)

    def callee(self, call: Term, depth: int) -> tuple[Term, tuple, Any]:
        key = (call, depth)
        if key in self.cache:
            return self.cache[key]
        if depth >= self.limits.callee_depth or call in self.active:
            return unknown("budget:callee_depth"), (), None
        target = self.concrete(self.expand(call[1], depth))
        if target is None:
            return unknown("unresolved:call_target"), (), None
        contract = self.contracts.get(target)
        if contract is None:
            return unknown(f"unverified:{target:#x}"), (), None
        if self.code_of(target) != target:
            return unknown("unsupported:proxy_dispatch"), (), None
        fn = next((f for f in contract.functions if f.solidity_signature == call[2]), None)
        if fn is None:
            return unknown(f"unsupported:callee_entry:{target:#x}:{call[2]}"), (), None
        sender = call[5] if len(call) > 5 else const(self.address, "address")
        lowerer = Lowerer(
            contract, sender=sender, this=const(target, "address"), code=const(self.code_of(target), "address")
        )
        self.active.add(call)
        try:
            guard, returns = lowerer.called(fn, list(call[3]), bool(call[4]))
            # Stateful external calls require interprocedural state transitions/reentrancy semantics.
            # Do not assume success or a post-state just because the caller did not inspect returndata.
            changes_state = fn.all_state_variables_written() or any(
                k[0] in ("act", "havoc", "raw") for e in lowerer.exits for k in e.store
            )
            if changes_state or lowerer.lost:
                detail = "static_callee_write" if call[4] else "stateful_callee"
                result = unknown(f"unsupported:{detail}:{target:#x}:{call[2]}"), (), fn
            else:
                result = self.expand(guard, depth + 1), tuple(self.expand(v, depth + 1) for v in returns), fn
        finally:
            self.active.remove(call)
        self.cache[key] = result
        return result

    def expand(self, t: Any, depth: int = 0) -> Any:
        if isinstance(t, Term):
            key = (t, depth)
            if key not in self.expanded:
                try:
                    self.expanded[key] = self._expand(t, depth)
                except BudgetExceeded as exc:
                    self.expanded[key] = unknown(f"budget:{exc}")
            return self.expanded[key]
        return self._expand(t, depth)

    def _expand(self, t: Any, depth: int = 0) -> Any:
        if not isinstance(t, Term):
            if isinstance(t, tuple):
                return tuple(self.expand(x, depth) for x in t)
            if isinstance(t, frozenset):
                return frozenset(self.expand(x, depth) for x in t)
            return t
        kind = t[0]
        if kind == "immutable":
            at = self.concrete(self.expand(t[1], depth))
            contract = self.contracts.get(at) if at is not None else None
            if contract is not None:
                offsets = immutable_offsets(contract)
                code = self.reads.code(self.code_of(at))
                value = immutable_value(code, offsets.get(t[2], ()))
                if value is not None:
                    return const(value)
            return unknown(f"unsupported:immutable:{t[2]}")
        call = t if kind == "call" else t[1] if kind in ("ok", "caught", "item", "abi", "retsize") else None
        if isinstance(call, Term) and call[0] == "call":
            found = self.callee(call, depth)
            guard, returns, fn = found
            if kind in ("ok", "caught"):
                return mk_not(guard) if kind == "caught" else guard
            if not returns:
                return guard if guard[0] == "unknown" else unknown(f"unsupported:return:{call[2]}")
            if kind == "retsize":
                from eth_abi.grammar import parse

                from .lower import _abi_static, _abi_type

                def size(parsed):
                    if parsed.is_array:
                        return parsed.arrlist[-1][0] * size(parsed.item_type)
                    return sum(size(c) for c in parsed.components) if hasattr(parsed, "components") else 32

                abis = [_abi_type(r.type) for r in fn.returns]
                if all(a is not None and _abi_static(a) for a in abis):
                    return const(sum(size(parse(a)) for a in abis if a is not None))
                return unknown("unsupported:dynamic_returndata")
            path = t[3] if kind == "abi" else (t[2],) if kind == "item" else (0,)
            value = returned_part(returns, path, t[4] if kind == "abi" else None)
            if value is None and fn is not None and path[0] < len(fn.returns):
                from slither.core.declarations import Structure
                from slither.core.solidity_types import ArrayType, UserDefinedType

                from .lower import project as project_value

                value, type_ = returns[path[0]], fn.returns[path[0]].type
                for step in path[1:]:
                    if isinstance(type_, UserDefinedType) and isinstance(type_.type, Structure):
                        field = type_.type.elems_ordered[step]
                        value = project_value(value, (("f", field.name),))
                        type_ = field.type
                    elif isinstance(type_, ArrayType):
                        value = project_value(value, (("k", const(step)),))
                        type_ = type_.type
                    else:
                        value = None
                        break
            if value is None:
                return unknown(f"unsupported:return_path:{path}")
            if kind == "item" and fn is not None and t[2] < len(fn.returns):
                type_ = str(fn.returns[t[2]].type)
                if type_.startswith("bytes") and type_[5:].isdigit():
                    value = mk("op", "shl", (value, const(8 * (32 - int(type_[5:])))))
                elif type_.startswith("int"):
                    value = mk("conv", "uint256", value)
            return value
        return mk(*(self.expand(x, depth) for x in t))


def compile_function(
    contract: Any,
    function: Any,
    address: int,
    reads: Reads,
    contracts: Any,
    limits: Limits = Limits(),
    code_of=None,
    bindings=None,
) -> Formula:
    lowerer = Lowerer(
        contract, this=const(address, "address"), code=const((code_of or (lambda x: x))(address), "address")
    )
    lowerer.success(function)
    parameters = tuple(parameter(p, i) for i, p in enumerate(function.parameters))
    selector = int.from_bytes(keccak(text=function.solidity_signature)[:4], "big")
    frame = {
        THIS: const(address, "address"),
        mk("sig"): const(selector, "bytes4"),
        CALLDATA: mk("enc", "abi.encodeWithSelector", (const(selector, "bytes4"), *parameters)),
    }
    linker = Linker(reads, contracts, address, limits, code_of, bindings)

    def linked(t: Term) -> Term:
        return linker.expand(replace_terms(t, frame))

    def location_frame(value: Any) -> Any:
        if isinstance(value, Term):
            return linked(value)
        if isinstance(value, tuple):
            return tuple(location_frame(part) for part in value)
        return value

    def guard(t: Term) -> Term:
        proxy = code_of is not None and code_of(address) != address
        return linked(
            mk_and(
                [
                    t,
                    TRUE if function.payable else mk_cmp("eq", mk("callvalue"), const(0)),
                    unknown("unsupported:proxy_dispatch") if proxy else TRUE,
                ]
            )
        )

    effects, transitions = [], []
    for exit_ in lowerer.exits:
        pc = guard(exit_.pc)
        # An unmodelled external transition can change later reads even when its return
        # value is discarded. Its success is not the only missing part of the semantics.
        for location, reached in exit_.store.items():
            if location[0] == "act":
                pc = mk_and([pc, mk_or([mk_not(linked(reached)), unknown("unsupported:external_transition")])])
        updates = []
        for location, value in exit_.store.items():
            kind = location[0]
            if kind in ("emit", "heap", "transient"):
                continue
            bound_location = location_frame(location)
            bound_value = linked(value)
            if kind == "act":
                target = ("act", replace_terms(location[1], frame), ())
                effects.append(
                    Effect(
                        "call", target, bound_value, mk_and([pc, bound_value, unknown("unsupported:external_effect")])
                    )
                )
            elif kind == "havoc":
                updates.append(Update(bound_location, unknown("unsupported:unresolved_state_update")))
                effects.append(
                    Effect(
                        "unknown", bound_location, bound_value, mk_and([pc, unknown("unsupported:unresolved_effect")])
                    )
                )
            else:
                updates.append(Update(bound_location, bound_value))
                change = mk_not(mk_cmp("eq", bound_value, linked(unwritten(location))))
                effects.append(Effect("write", bound_location, bound_value, mk_and([pc, change])))
        transitions.append(Transition(pc, tuple(updates)))
    return Formula(
        address,
        reads.block,
        function.solidity_signature,
        selector,
        parameters,
        mk_or([t.guard for t in transitions]),
        tuple(effects),
        tuple(transitions),
    )
