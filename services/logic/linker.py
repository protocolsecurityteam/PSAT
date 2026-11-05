"""Resolve verified code and entry-state call/dispatch dependencies."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from eth_utils.crypto import keccak

from .abi_values import (
    abi_signature,
    describe,
    getter_shape,
    inferred,
    static_word,
    static_words,
    strict_decoder,
    transfer,
)
from .immutables import immutable_offsets, immutable_value
from .lower import Lowerer
from .model import BudgetExceeded, CallFrame, Limits, Reads
from .solver import Translation, number
from .terms import (
    CALLDATA,
    FALSE,
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
    subterms,
    unknown,
)

# Kinds a value can't be read at the block without: who calls, with what, and what isn't modelled.
_SYMBOLIC = frozenset(
    {"caller", "origin", "signer", "arg", "callvalue", "calldatasize", "unknown", "opaque", "call", "delegate"}
)


def _selector(signature: str | None) -> int | None:
    return int.from_bytes(keccak(text=signature)[:4], "big") if signature else None


class _Overlay(Mapping):
    """``contracts`` with the code at one address replaced: a proxy's own, where ``contracts`` gives its
    implementation's."""

    def __init__(self, contracts: Any, at: int, own: Any):
        self.contracts, self.at, self.own = contracts, at, own

    def get(self, address: Any, default: Any = None) -> Any:
        return self.own if address == self.at else self.contracts.get(address, default)

    def record_code(self, address, code, contract):
        record = getattr(self.contracts, "record_code", None)
        if record is not None:
            record(address, code, contract)

    def own_code(self, address):
        own = getattr(self.contracts, "own_code", None)
        return own(address) if own is not None else self.own if address == self.at else self.contracts.get(address)

    def __getitem__(self, address: Any) -> Any:
        found = self.get(address)
        if found is None:
            raise KeyError(address)
        return found

    def __contains__(self, address: object) -> bool:
        return self.get(address) is not None

    def __iter__(self):
        return iter(self.contracts)

    def __len__(self) -> int:
        return len(self.contracts)


def special_entry(contract, kind: str) -> Any:
    """The deployed ``fallback`` or ``receive``. Slither also lists the overridden ones, and its
    ``fallback_function``/``receive_function`` return the first declared, a base contract's."""
    flag = "is_fallback" if kind == "fallback" else "is_receive"
    return next((f for f in contract.functions if getattr(f, flag) and not f.is_shadowed), None)


def _entry(contract, signature) -> Any:
    """Compiler entrypoints, including the scalar getters Slither leaves as declarations."""
    from types import SimpleNamespace

    from .layout import _size

    # A public state variable can override a function but never be overridden, so its getter is
    # the deployed entry even where Slither keeps the base function unshadowed.
    var = next(
        (v for v in contract.state_variables if v.visibility == "public" and abi_signature(v) == signature),
        None,
    )
    if var is None:
        return next(
            (
                f
                for f in contract.functions_entry_points
                if abi_signature(f) == signature and not (f.is_constructor or f.is_fallback or f.is_receive)
            ),
            None,
        )
    keys, value_type = getter_shape(var.type)
    if _size(value_type) is None:
        return None
    return SimpleNamespace(
        name=var.name,
        compilation_unit=contract.compilation_unit,
        solidity_signature=signature,
        entry_point=None,
        parameters=[SimpleNamespace(name=f"key{i}", type=t) for i, t in enumerate(keys)],
        returns=[SimpleNamespace(type=value_type)],
        all_state_variables_written=lambda: [],
        all_slithir_operations=lambda: [],
    )


def runtime_signatures(contract):
    return sorted(
        {
            abi_signature(f)
            for f in contract.functions_entry_points
            if not (f.is_constructor or f.is_fallback or f.is_receive)
        }
        | {abi_signature(v) for v in contract.state_variables if v.visibility == "public"}
    )


def runtime_entry(contract, selector, size):
    """Solidity dispatcher selection, including fallback and receive entries."""
    if size is None or size >= 4:
        found = [s for s in runtime_signatures(contract) if _selector(s) == selector]
        if len(found) == 1:
            entry = _entry(contract, found[0])
            if entry is None:
                raise ValueError("unsupported:callee_entry")
            return entry
        if len(found) > 1:
            raise ValueError("unsupported:selector_collision")
    if size == 0:
        received = special_entry(contract, "receive")
        if received is not None:
            return received
    return special_entry(contract, "fallback")


def _forwarding_only(store: dict, at: int) -> bool:
    """Exactly one delegate effect, and no other persistent effects in the dispatcher."""
    calls = [k for k in store if k[0] == "act"]
    if len(calls) != 1 or calls[0][1][0] != "delegate" or len(calls[0][1]) != 2:
        return False
    allowed = {calls[0], ("havoc", const(at, "address"), "*elsewhere", "delegatecall")}
    return all(k in allowed for k in store)


def _unresolved_dispatch(guard: Term) -> bool:
    return contains(guard, frozenset({"unknown", "opaque"}))


class _DispatchTranslation(Translation):
    """Dispatch validation reads concrete facts only; caller-set enumeration is a later stage."""

    def _translate(self, t):
        # Nested callees can retain an invoking frame's leaves until the outer
        # lowering returns. Default selector/address values are not those facts.
        if t[0] in {"sig", "this", "frame_value"}:
            return self.missing(t, "unresolved:call_frame")
        return super()._translate(t)

    def _load(self, t):
        if contains(t, _SYMBOLIC):
            return self.missing(t, "symbolic dispatch storage")
        return super()._load(t)


class Linker:
    """Follow verified callees in their actual call frames; never ask eth_call for a verdict."""

    def __init__(
        self, reads: Reads, contracts: Any, address: int, limits: Limits, code_of=None, bindings=None, own_code=None
    ):
        self.reads, self.contracts, self.address, self.limits = reads, contracts, address, limits
        self.code_of = code_of or (lambda at: at)
        self.own_code = own_code
        self.bindings = bindings
        self.state_specialized = False
        self.cache: dict[tuple, Any] = {}
        self.active: set[Term] = set()
        self.expanded: dict[tuple[Term, int], Term] = {}
        self.journal = None
        self.parent: Linker | None = None
        self._frames = 1

    def next_frame(self):
        if self.journal is not None:
            return None  # Journal.attach supplies durable, replay-stable frame identities.
        root = self
        while root.parent is not None:
            root = root.parent
        root._frames += 1
        return root._frames

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
        if contains(bound, _SYMBOLIC):
            return None
        evaluator = Translation(self.reads, self.contracts, self.address, limits=self.limits, bindings=self.bindings)
        v = evaluator.translate(t)
        if any(i.kind == "budget" for i in evaluator.issues):
            raise BudgetExceeded("callee resolution reads")
        value = None if evaluator.issues else number(v)
        if value is not None and contains(t, frozenset({"load", "rawload", "balance", "time", "codesize", "codehash"})):
            self.state_specialized = True
            if self.journal is not None:
                self.journal.specialized = True
        return value

    def callee(self, call: Term, depth: int) -> tuple[Term, tuple, Any]:
        key = (call, depth)
        if key in self.cache:
            guard, returns, at = self.cache[key]
            contract = self.contracts.get(at)
            return guard, returns, _entry(contract, call[2]) if contract is not None else None
        if depth >= self.limits.callee_depth or call in self.active:
            if self.journal is not None:
                self.journal.suspend("callee_depth", (call, depth))
            return unknown("budget:callee_depth"), (), None
        target = self.concrete(self.expand(call[1], depth))
        if target is None:
            return unknown("unresolved:call_target"), (), None
        if not self.reads.code(target):
            return unknown(f"unsupported:empty_runtime_call:{target:#x}"), (), None
        contract = self.contracts.get(target)
        if contract is None:
            return unknown(f"unverified:{target:#x}"), (), None
        fn = _entry(contract, call[2])
        if fn is None:
            return unknown(f"unsupported:callee_entry:{target:#x}:{call[2]}"), (), None
        encoded = call[7] if len(call) > 7 else tuple(inferred(v) for v in call[3])
        decoded = tuple(describe(p.type) for p in fn.parameters)
        if len(encoded) < len(decoded) or len(call[3]) != len(encoded):
            return unknown("unsupported:callee_argument_abi"), (), fn
        # The callee's code decodes its arguments, the caller's the return data: each by its own ABI coder.
        arguments = [transfer(v, a, b, strict=strict_decoder(contract)) for v, a, b in zip(call[3], encoded, decoded)]
        expected = call[6] if len(call) > 6 else None
        actual = tuple(describe(r.type) for r in fn.returns)
        sender = call[5] if len(call) > 5 else const(self.address, "address")
        caller = self.contracts.get(sender[1]) if sender[0] == "const" else None
        dispatch = TRUE
        if self.code_of(target) != target:
            frame = {
                mk("sig"): const(_selector(call[2]), "bytes4"),
                CALLDATA: unknown("callee:msg.data"),
                mk("callvalue"): const(0) if call[4] else unknown("callee:msg.value"),
            }
            dispatch = self.dispatch(
                target, call[2], frame, sender, depth + 1, forwards_return=True, static=bool(call[4])
            )
            if _unresolved_dispatch(dispatch):
                return dispatch, (), fn
        lowerer = Lowerer(
            contract,
            sender=sender,
            this=const(target, "address"),
            code=const(self.code_of(target), "address"),
            journal=self.journal,
            frame_identity=self.next_frame(),
        )
        lowerer.resolver = self
        self.active.add(call)
        try:
            guard, returns = lowerer.called(fn, [pair[0] for pair in arguments], bool(call[4]))
            if any(e.halted for e in lowerer.exits):
                return unknown("unsupported:callee_raw_return"), (), fn
            if len(returns) != len(actual) or (expected is not None and len(expected) > len(actual)):
                return unknown("unsupported:callee_return_abi"), (), fn
            cleaned = [transfer(v, t, t) for v, t in zip(returns, actual)]
            guard = mk_and([dispatch, guard, *(pair[1] for pair in arguments), *(pair[1] for pair in cleaned)])
            if expected is not None:
                strict = call[8] if len(call) > 8 else strict_decoder(caller)
                decoded_returns = [transfer(v[0], a, b, strict=strict) for v, a, b in zip(cleaned, actual, expected)]
                guard = mk_and([guard, *(pair[1] for pair in decoded_returns)])
                returns = tuple(pair[0] for pair in decoded_returns)
            else:
                returns = tuple(pair[0] for pair in cleaned)
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
        self.cache[key] = (result[0], result[1], target)
        return result

    def dispatch(
        self,
        at: int,
        signature: str,
        frame: dict,
        sender: Term,
        depth: int,
        forwards_return: bool = False,
        state: dict | None = None,
        code: int | None = None,
        trail: tuple[int, ...] = (),
        static: bool = False,
    ) -> Term:
        """When a call of ``signature`` at proxy ``at`` runs the implementation ``code_of`` names, read from the
        proxy's own code at the block: its fallback forwards this calldata by ``delegatecall`` to a target that
        reads as that implementation, on every path that returns. Anything else stays unsupported."""
        self.state_specialized = True
        if self.journal is not None:
            self.journal.specialized = True
        if state and any(k[0] not in ("heap", "emit") for k in state):
            # Dispatch can depend on foreign helpers and transient state as well as its
            # own persistent slots. Updated dispatch is outside this first transition slice.
            return unknown("unsupported:updated_proxy_dispatch")
        code = at if code is None else code
        if code in trail:
            return unknown(f"unsupported:proxy_dispatch:cycle:{code:#x}")
        if depth >= self.limits.callee_depth:
            if self.journal is not None:
                self.journal.suspend("callee_depth", (at, code, signature, depth))
            return unknown("budget:callee_depth")
        own = self.own_code(code) if self.own_code is not None else None
        record = getattr(self.contracts, "record_code", None)
        if record is not None:
            record(at, code, own)
        if own is None:
            reason = "target" if code != at else "source"
            return unknown(f"unsupported:proxy_dispatch:{reason}:{code:#x}")
        selector = _selector(signature)
        if any(
            _selector(abi_signature(f)) == selector and not (f.is_constructor or f.is_fallback or f.is_receive)
            for f in own.functions_entry_points
        ) or any(v.visibility == "public" and _selector(abi_signature(v)) == selector for v in own.state_variables):
            return unknown(f"unsupported:proxy_selector:{at:#x}:{signature}")
        fallback = special_entry(own, "fallback")
        if fallback is None:
            return unknown(f"unsupported:proxy_fallback:{at:#x}")
        # The fallback's own storage and immutables are the proxy's: read through its layout and its bytecode, never
        # the implementation's that ``contracts`` and ``code_of`` give for this address.
        mine = Linker(
            self.reads,
            _Overlay(self.contracts, at, own),
            self.address,
            self.limits,
            lambda a: code if a == at else self.code_of(a),
            self.bindings,
            self.own_code,
        )
        mine.journal = self.journal
        mine.parent = self
        lowerer = Lowerer(
            own,
            sender=sender,
            this=const(at, "address"),
            code=const(code, "address"),
            journal=self.journal,
            frame_identity=self.next_frame(),
            frame=CallFrame(
                const(code, "address"),
                const(at, "address"),
                sender,
                frame.get(mk("callvalue"), mk("callvalue")),
                frame.get(CALLDATA, CALLDATA),
                static,
            ),
        )
        lowerer.resolver = mine
        lowerer.success(fallback)
        paths = []
        implementation = self.code_of(at)
        for exit_ in lowerer.exits:
            pc = mine.expand(replace_terms(exit_.pc, frame), depth)
            if pc == FALSE or mine._refuted(pc):
                continue
            actions = [k for k in exit_.store if k[0] == "act"]
            if not actions:
                return unknown(f"unsupported:proxy_dispatch:undelegated:{at:#x}")
            if not _forwarding_only(exit_.store, at):
                return unknown(f"unsupported:proxy_dispatch:state:{at:#x}")
            executed = {mine.expand(replace_terms(k[1], frame), depth) for k in actions}
            found = set(subterms(pc, "delegate"))
            if found != executed:
                return unknown(f"unsupported:proxy_dispatch:unchecked:{at:#x}")
            # A way the fallback returns without the delegate running: not the implementation's call, wherever
            # the solver can't refute it (an admin's own branch, on a selector it can evaluate).
            alone = replace_terms(pc, {d: FALSE for d in found})
            if mine._refuted(alone):
                alone = FALSE
            through = mk_and([replace_terms(pc, {d: TRUE for d in found}), mk_not(alone)])
            if alone != FALSE:
                return unknown(f"unsupported:proxy_dispatch:undelegated:{at:#x}")
            returned = tuple(mine.expand(replace_terms(v, frame), depth) for v in (exit_.ret or ()))
            if forwards_return and (len(found) != 1 or returned != (mk("opaque", "forwarded", tuple(found)),)):
                return unknown(f"unsupported:proxy_dispatch:returndata:{at:#x}")
            tail = TRUE
            for delegate in found:
                try:
                    target = mine.concrete(mine.expand(delegate[1], depth)) if len(delegate) == 2 else None
                except BudgetExceeded as exc:
                    if self.journal is not None:
                        self.journal.suspend("input_budget", (delegate, depth))
                    return unknown(f"budget:{exc}")
                if target is None or not 0 < target < 2**160:
                    return unknown(f"unsupported:proxy_dispatch:target:{at:#x}")
                if target != implementation:
                    tail = self.dispatch(
                        at,
                        signature,
                        frame,
                        sender,
                        depth + 1,
                        forwards_return,
                        code=target,
                        trail=(*trail, code),
                        static=static,
                    )
                    if _unresolved_dispatch(tail):
                        return tail
            # Pin each layer's storage using that layer's layout before combining it
            # with the next layer, whose variables can have the same names at other slots.
            paths.append(mk_and([mine.pinned(through, at), tail]))
        guard = mk_or(paths)
        payable = TRUE if fallback.payable else mk_cmp("eq", frame.get(mk("callvalue"), mk("callvalue")), const(0))
        return mk_and([guard, payable])

    def pinned(self, t: Term, at: int) -> Term:
        """``t`` with each read of ``at``'s named storage replaced by its value at the block: outside this view the
        same term reads the implementation's layout. A read that isn't one value (keyed by the caller) is unknown."""
        evaluator = Translation(self.reads, self.contracts, self.address, limits=self.limits, bindings=self.bindings)
        values = {}
        for load in subterms(t, "load"):
            if load[1] != const(at, "address"):
                continue
            value = number(evaluator.translate(load)) if not contains(load, _SYMBOLIC) else None
            values[load] = (
                const(value) if value is not None and not evaluator.issues else unknown("unsupported:proxy_storage")
            )
        return replace_terms(t, values) if values else t

    def _refuted(self, t: Term) -> bool:
        """Whether ``t`` is false at the block whatever its symbolic parts: some conjunct of every disjunct evaluates
        false (an admin branch on a selector this call doesn't carry)."""
        if t[0] == "or":
            return all(self._refuted(x) for x in t[1])
        if t[0] == "and":
            return any(self._refuted(x) for x in t[1])
        evaluator = _DispatchTranslation(
            self.reads, self.contracts, self.address, limits=self.limits, bindings=self.bindings
        )
        try:
            return evaluator.truth(t) is False
        except BudgetExceeded:
            return False

    def expand(self, t: Any, depth: int = 0) -> Any:
        if isinstance(t, Term):
            key = (t, depth)
            if key not in self.expanded:
                try:
                    self.expanded[key] = self._expand(t, depth)
                except BudgetExceeded as exc:
                    if self.journal is not None:
                        self.journal.suspend("input_budget", (t, depth))
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
        if kind == "load" and len(t) > 4 and t[4][2] is None:
            from .cells import annotate

            code = self.concrete(self.expand(t[4][1], depth))
            source = self.own_code(code) if code is not None and self.own_code is not None else None
            if source is None and code is not None:
                lookup = getattr(self.contracts, "own_code", None)
                source = lookup(code) if lookup is not None else self.contracts.get(code)
            if source is not None:
                location = annotate(source, t[4][1], (t[1], t[2], t[3]))
                if location[3][2] is not None:
                    t = mk("load", *location)
        if kind == "calldata_selector":
            from .memory import buffer_uint

            return buffer_uint(self.expand(t[1], depth), 0, 4, padded=True) or unknown("unresolved:call_selector")
        if kind == "len":
            from .abi_values import encoded_region

            layout = encoded_region(self.expand(t[1], depth))
            if layout is not None:
                return const(layout[0])
        if kind == "elem":
            from .lower import element

            container, index = self.expand(t[1], depth), self.expand(t[2], depth)
            if container[0] in ("array", "abi_array", "load", "ite", "upd"):
                projected = element(container, index)
                return self.expand(projected, depth) if projected != t else projected
        if kind == "immutable":
            at = self.concrete(self.expand(t[1], depth))
            contract = (
                (self.own_code(at) if self.own_code is not None else self.contracts.get(at)) if at is not None else None
            )
            if contract is not None and at is not None:
                offsets = immutable_offsets(contract)
                code = self.reads.code(at)
                value = immutable_value(code, offsets.get(t[2], ()))
                if value is not None:
                    return const(value)
            return unknown(f"unsupported:immutable:{t[2]}")
        call = t if kind == "call" else t[1] if kind in ("ok", "caught", "item", "abi", "retsize", "retword") else None
        if kind in ("retsize", "retword") and isinstance(call, Term):
            if call[0] == "return_buffer":
                data = call[1]
                if data[0] == "ite":
                    return self.expand(
                        mk(
                            "ite",
                            data[1],
                            mk(kind, mk("return_buffer", data[2]), *t[2:]),
                            mk(kind, mk("return_buffer", data[3]), *t[2:]),
                        ),
                        depth,
                    )
                from .memory import buffer_memory, memory_word

                layout = buffer_memory(data)
                if layout is None:
                    return unknown("unsupported:returndata_bytes")
                return (
                    const(layout[0])
                    if kind == "retsize"
                    else (memory_word(layout[1], 32 * t[2]) or unknown("unsupported:returndata_word"))
                )
            if call[0] == "returndata_empty":
                return const(0) if kind == "retsize" else unknown("unsupported:empty_returndata")
            if call[0] == "ite":
                return mk(
                    "ite",
                    self.expand(call[1], depth),
                    self.expand(mk(kind, call[2], *t[2:]), depth),
                    self.expand(mk(kind, call[3], *t[2:]), depth),
                )
        if isinstance(call, Term) and call[0] == "call":
            found = self.callee(call, depth)
            guard, returns, fn = found
            if kind in ("ok", "caught"):
                return mk_not(guard) if kind == "caught" else guard
            if kind in ("retword", "retsize"):
                if fn is None:
                    return guard if guard[0] == "unknown" else unknown("unsupported:returndata_layout")
                shape = (
                    "abi_type",
                    "tuple",
                    tuple(("abi_field", str(i), describe(r.type)) for i, r in enumerate(fn.returns)),
                )
                count = static_words(shape)
                if count is None:
                    return unknown("unsupported:dynamic_returndata")
                data = (
                    const(32 * count)
                    if kind == "retsize"
                    else static_word(mk("struct", tuple(str(i) for i in range(len(returns))), returns), shape, t[2])
                )
                if data is None:
                    return unknown("unsupported:returndata_word")
                return mk("ite", guard, data, unknown("unsupported:revert_data")) if guard != TRUE else data
            if not returns:
                return guard if guard[0] == "unknown" else unknown(f"unsupported:return:{call[2]}")
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
