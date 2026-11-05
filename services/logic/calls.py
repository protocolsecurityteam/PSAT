"""Symbolic external-call summaries over an explicit world state, independent of caller locals."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from .abi_values import (
    abi_signature,
    decode_buffer,
    decode_static,
    describe,
    static_memory_size,
    static_words,
    strict_decoder,
    transfer,
)
from .linker import Linker, _selector, runtime_entry, runtime_signatures
from .lower import Lowerer, State, _acted, _solc_version, _spent, merge
from .model import BudgetExceeded, CallFrame, CallRequest, CallResult, DeferredCall, Update
from .terms import (
    CALLDATA,
    CALLER,
    FALSE,
    TRUE,
    Term,
    conjuncts,
    const,
    mk,
    mk_and,
    mk_cmp,
    mk_ite,
    mk_not,
    mk_op,
    subterms,
    unknown,
)


class CallExecutor(Linker):
    """Compose supported high-level calls over one shared storage state and separate call frames."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executing: set[tuple[int, str]] = set()

    def code_contract(self, target):
        if self.own_code is not None:
            source = self.own_code(target)
            if source is not None or self.code_of(target) != target:
                return source
        own = getattr(self.contracts, "own_code", None)
        if own is None and self.code_of(target) != target:
            return None
        return own(target) if own is not None else self.contracts.get(target)

    def payload_shape(self, data):
        from .memory import buffer_length, buffer_memory, buffer_min_length, buffer_uint

        layout = buffer_memory(data)
        if layout is not None:
            head = buffer_uint(data, 0, 4, padded=True)
            return layout[0], self.concrete(self.expand(head)) if head is not None else None
        if data[0] == "bytes_prefix" and len(data[1]) >= 4:
            return None, int.from_bytes(data[1][:4], "big")
        if data[0] == "bytes_patch":
            length = buffer_length(data)
            size = self.concrete(self.expand(length)) if length is not None else None
            if size is not None and size < 4:
                return size, None
            head = buffer_uint(data, 0, 4, padded=True) if buffer_min_length(data) >= 4 else None
            return size, self.concrete(self.expand(head)) if head is not None else None
        if data[:2] == ("enc", "abi.encodeWithSignature") and data[2] and data[2][0][0] == "const":
            return None, _selector(data[2][0][1])
        if data[:2] == ("enc", "abi.encodeWithSelector") and data[2]:
            return None, self.concrete(self.expand(mk("conv", "uint32", data[2][0])))
        return None, None

    def decode_entry(self, contract, fn, target, size, word, mode, *, data=None):
        """The selected entry's ABI decoder, shared by concrete and symbolic dispatch."""
        fallback = fn is not None and (getattr(fn, "is_fallback", False) or getattr(fn, "is_receive", False))
        if fn is None or fallback:
            return mk("call", target, "fallback()", (), mode == "staticcall", None, None, (), True), TRUE
        signature = abi_signature(fn)
        types = tuple(describe(p.type) for p in fn.parameters)
        widths = [static_words(t) for t in types]
        version, strict = _solc_version(fn), strict_decoder(contract)
        if version is None or strict is None:
            return None
        dynamic = any(w is None for w in widths)
        if dynamic and (
            data is None
            or version != [0, 8]
            or not strict
            or any(w is None and t[1] not in ("bytes", "string") for t, w in zip(types, widths))
            or any(
                w is None and getattr(p, "location", None) not in ("memory", "calldata")
                for p, w in zip(fn.parameters, widths)
            )
        ):
            return None
        count = sum(w if w is not None else 1 for w in widths)
        padded_legacy = version < [0, 5] and not strict
        if not padded_legacy and isinstance(size, int) and 4 + 32 * count > size:
            call = mk(
                "call",
                target,
                signature,
                tuple(unknown("short_calldata") for _ in types),
                mode == "staticcall",
                None,
                None,
                types,
                True,
            )
            return call, FALSE
        if _spent(count):
            return None
        arguments, guards, offset = [], [], 4
        extent = const(size) if isinstance(size, int) else size
        if dynamic:
            guards.append(mk_cmp("ge", mk("conv", "int256", mk_op("sub", (extent, const(4)))), const(32 * count)))
        elif not padded_legacy and count and not isinstance(size, int):
            guards.append(mk_cmp("le", const(4 + 32 * count), size))
        free = const(128)
        for parameter, type_, width in zip(fn.parameters, types, widths):
            allocation = None
            if width is None:
                relative = word(offset)
                position = mk_op("add", (const(4), relative))
                length = mk("elem", data, position)
                start = mk_op("add", (position, const(32)))
                value = mk("bytes_slice", data, start, length)
                valid = mk_and(
                    [
                        mk_cmp("le", relative, const(2**64 - 1)),
                        mk_cmp(
                            "lt",
                            mk("conv", "int256", mk_op("add", (position, const(31)))),
                            mk("conv", "int256", extent),
                        ),
                        mk_cmp("le", length, const(2**64 - 1)),
                        mk_cmp("le", mk_op("add", (start, length)), extent),
                    ]
                )
                if getattr(parameter, "location", None) == "memory":
                    rounded = mk_op("and", (mk_op("add", (length, const(31))), const(2**256 - 32)))
                    allocation = mk_op("add", (const(32), rounded))
            else:
                raw = tuple(word(offset + 32 * i) for i in range(width))
                value, valid = decode_static(raw, type_, strict)
                if dynamic and getattr(parameter, "location", None) == "memory":
                    space = static_memory_size(type_)
                    if space is None:
                        return None
                    allocation = const(space)
            if allocation is not None:
                after = mk_op("add", (free, allocation))
                guards.extend([mk_cmp("ge", after, free), mk_cmp("le", after, const(2**64 - 1))])
                free = after
            arguments.append(value)
            guards.append(valid)
            offset += 32 * (width if width is not None else 1)
        call = mk("call", target, signature, tuple(arguments), mode == "staticcall", None, None, types, True)
        return call, mk_and(guards)

    def handler(self, depth: int, static: bool = False):
        def follow(request: CallRequest) -> CallResult:
            state = State(TRUE, {}, {u.location: u.value for u in request.storage})
            is_static = static or bool(request.call[4]) or bool(request.frame and request.frame.static)
            try:
                after, values = self.execute(request, state, depth, is_static)
            except BudgetExceeded as exc:
                if self.journal is not None:
                    self.journal.suspend("input_budget", (request.call, state))
                after, values = self.unresolved(request.call, state, f"budget:{exc}", is_static)
            if request.raw is not None:
                # A logical return is not a proof against callee resource exhaustion. Low-level
                # callers can continue after that failure, unlike a required high-level call.
                success = mk_and([after.pc, mk_not(mk_cmp("eq", request.raw, const(0)))])
                data = values[0] if values else unknown("unsupported:raw_return_data")
                data = mk_ite(success, data, unknown("unsupported:revert_data"))
                after = merge(
                    [
                        State(success, {}, after.store),
                        State(mk_not(success), {}, state.store),
                    ]
                )
                return CallResult(TRUE, (success, data), tuple(Update(k, v) for k, v in after.store.items()))
            return CallResult(after.pc, tuple(values), tuple(Update(k, v) for k, v in after.store.items()))

        return follow

    def dispatch_cases(self, contract, data, *, fallback_only=False):
        """Disjoint runtime domains. Decoder failure never selects fallback."""
        from .memory import buffer_length, buffer_uint

        size, selector = self.payload_shape(data)
        if not fallback_only and (selector is not None or (size is not None and size < 4)):
            return [(runtime_entry(contract, selector, size), TRUE)]
        length, head = buffer_length(data), buffer_uint(data, 0, 4, padded=True)
        if length is None or head is None:
            raise ValueError("unsupported:calldata_extent")
        named = [
            (signature, mk_and([mk_cmp("le", const(4), length), mk_cmp("eq", head, const(_selector(signature)))]))
            for signature in runtime_signatures(contract)
        ]
        # Keep each exclusion explicit: overlapping invocations can carry these
        # same conditions through multiple forwarding layers.
        fallback_guard = mk_and(mk_not(guard) for _, guard in named)
        received = next((f for f in contract.functions_entry_points if f.is_receive), None)
        if received is not None:
            fallback_guard = mk_and([fallback_guard, mk_not(mk_cmp("eq", length, const(0)))])
        fallback = next((f for f in contract.functions_entry_points if f.is_fallback), None)
        if fallback_only:
            return [(fallback, fallback_guard)]
        # Resolve a named body only after its domain is known reachable. An
        # excluded getter must not require a decoder or a synthetic body.
        cases: list[tuple[Any, Term]] = list(named)
        if received is not None:
            cases.append((received, mk_cmp("eq", length, const(0))))
        cases.append((fallback, fallback_guard))
        return cases

    def root(self, data, *, fallback_only=False):
        """Execute deployed runtime without an outer caller's ABI return decoder."""
        state = State(TRUE, {}, {})
        frame = CallFrame(const(self.address, "address"), const(self.address, "address"), CALLER, mk("callvalue"), data)
        call = mk("call", frame.code, "", (), False, None, None, (), True)
        try:
            request = CallRequest(call, (), frame.value, frame=frame, calldata=data)
            after, _ = self.execute(request, state, -1, False, root=True, fallback_only=fallback_only)
            return after
        except DeferredCall as exc:
            if self.journal is not None:
                self.journal.suspend(
                    "call",
                    {"kind": "call", "call": call, "state": state, "frame": frame.record(), "reason": exc.reason},
                )
            return self.unresolved(call, state, exc.reason, False)[0]

    def unresolved(self, call, state, reason, static):
        gap = unknown(reason)
        after = State(mk_and([state.pc, gap]), state.env, state.store, state.ret)
        if not static:
            after = _acted(after, gap)
        values = tuple(unknown(reason) for _ in (call[6] or ()))
        return after, values

    def execute(self, request: CallRequest, state, depth, static, *, root=False, fallback_only=False):
        call, value, gas, caught = (
            request.call,
            request.value,
            request.gas,
            request.caught,
        )
        mode = request.mode or ("staticcall" if call[4] else "call")

        def unresolved(reason):
            if self.journal is not None:
                raise DeferredCall(reason)
            return self.unresolved(call, state, reason, static)

        if mode not in ("call", "staticcall", "delegatecall"):
            return unresolved("unsupported:call_mode")
        delegated = mode == "delegatecall"
        if delegated and request.frame is None:
            return unresolved("unsupported:delegate_frame")
        if caught:
            return unresolved("unsupported:stateful_try")
        if gas is not None:
            return unresolved("unsupported:explicit_call_gas")
        if not root and not delegated and value not in (None, const(0)):
            return unresolved("unsupported:call_value_transfer")
        if depth >= self.limits.callee_depth:
            if self.journal is not None:
                self.journal.suspend("callee_depth", (call, state, value, gas, caught, depth))
            return unresolved("budget:callee_depth")
        if any(k[:2] == ("havoc", "*world*") for k in state.store):
            return unresolved("unsupported:call_after_unknown_transition")
        target = self.concrete(self.expand(call[1], depth))
        if target is None:
            return unresolved("unresolved:call_target")
        # Empty runtime can be an ordinary account or a precompile. Do not fetch
        # Solidity source or assume call success/failure without modeling that distinction.
        if not self.reads.code(target):
            return unresolved(f"unsupported:empty_runtime_call:{target:#x}")
        contract = self.code_contract(target)
        if contract is None:
            return unresolved(f"unverified:{target:#x}")
        data = (
            request.calldata
            if request.calldata is not None
            else mk("enc", "abi.encodeWithSignature", (const(call[2], "string"), *call[3]), call[7])
        )
        try:
            cases = self.dispatch_cases(contract, data, fallback_only=fallback_only)
        except ValueError as exc:
            return unresolved(str(exc))
        outcomes = []
        for fn, domain in cases:
            branch = State(mk_and([state.pc, request.input_guard, domain]), state.env, state.store, state.ret)
            if fn is None or branch.pc == FALSE:
                continue
            if _spent(1):
                return unresolved("budget:dispatch")
            if isinstance(fn, str):
                try:
                    fn = runtime_entry(contract, _selector(fn), None)
                except ValueError as exc:
                    return unresolved(str(exc))
                if fn is None:
                    return unresolved("unsupported:callee_entry")
            selected = request
            if call[2] == "":
                from .memory import buffer_length, buffer_uint

                size, _ = self.payload_shape(data)
                length = buffer_length(data)
                if length is None:
                    return unresolved("unsupported:calldata_extent")
                decoded = self.decode_entry(
                    contract,
                    fn,
                    call[1],
                    size if size is not None else length,
                    lambda i: buffer_uint(data, i, 32, padded=True),
                    mode,
                    data=data,
                )
                if decoded is None:
                    return unresolved("unsupported:callee_input_decoder")
                selected = replace(request, call=decoded[0], input_guard=mk_and([request.input_guard, decoded[1]]))
            if selected.input_guard == FALSE:
                continue
            after, values = self.execute_entry(selected, branch, depth, static, target, contract, fn, data, root=root)
            outcomes.append(State(after.pc, state.env, after.store, tuple(values)))
        if not outcomes:
            return State(FALSE, state.env, state.store, state.ret), ()
        combined = merge(outcomes)
        return State(combined.pc, state.env, combined.store, state.ret), combined.ret or ()

    def execute_entry(self, request, state, depth, static, target, contract, fn, data, *, root=False):
        call, value, raw = request.call, request.value, request.raw is not None
        mode = request.mode or ("staticcall" if call[4] else "call")

        def unresolved(reason):
            if self.journal is not None:
                raise DeferredCall(reason)
            return self.unresolved(call, state, reason, static)

        fallback = getattr(fn, "is_fallback", False) or getattr(fn, "is_receive", False)
        active = target, abi_signature(fn)
        recursive = active in self.executing
        if recursive and self.journal is None:
            return unresolved("budget:recursive_call")
        sender = (
            request.frame.storage
            if request.frame is not None
            else (call[5] if len(call) > 5 and call[5] is not None else const(self.address, "address"))
        )
        encoded = call[7]
        decoded = tuple(describe(p.type) for p in fn.parameters)
        if fallback:
            given = [(data, TRUE)] if fn.parameters else []
        elif len(encoded) < len(decoded) or len(call[3]) != len(encoded) or (raw and len(encoded) != len(decoded)):
            return unresolved("unsupported:callee_argument_abi")
        else:
            given = [transfer(v, a, b, strict=strict_decoder(contract)) for v, a, b in zip(call[3], encoded, decoded)]
        # A static frame cannot perform a state-changing instruction, even a same-value write.
        # Conservatively reject functions containing such instructions when path-sensitive
        # static instruction effects are not represented by this lowering.
        if static and (
            fn.all_state_variables_written()
            or any(
                type(ir).__name__ == "EventCall"
                or getattr(getattr(ir, "function", None), "name", "").split("(")[0]
                in {
                    "sstore",
                    "tstore",
                    "create",
                    "create2",
                    "selfdestruct",
                    "suicide",
                    "log0",
                    "log1",
                    "log2",
                    "log3",
                    "log4",
                }
                for ir in fn.all_slithir_operations()
            )
        ):
            return unresolved("unsupported:static_effect")
        caller = request.frame or CallFrame(
            unknown("unrecorded:caller_code"),
            sender,
            CALLER,
            mk("callvalue"),
            CALLDATA,
        )
        frame = (
            caller
            if root
            else caller.enter(
                mode,
                const(target, "address"),
                const(target, "address"),
                data,
                value,
            )
        )
        frame = replace(frame, static=static)
        record = getattr(self.contracts, "record_code", None)
        if record is not None and frame.storage[0] == "const":
            record(frame.storage[1], frame.code[1], contract)
        lowerer = Lowerer(
            contract,
            sender=frame.sender,
            this=frame.storage,
            code=frame.code,
            call_handler=self.handler(depth + 1, static),
            journal=self.journal,
            frame=frame,
            frame_identity=self.next_frame(),
        )
        lowerer.resolver = self
        if not recursive:
            self.executing.add(active)
        try:
            exits = lowerer.called_paths(
                fn, [v for v, _ in given], state.store, guard=mk_and([state.pc, request.input_guard])
            )
        finally:
            if not recursive:
                self.executing.remove(active)
        # A qualification on an impossible branch must not erase the reachable
        # executions. This only removes guards refuted at the pinned snapshot;
        # caller-dependent or unanswered guards remain in the relation.
        reached = []
        for exit_ in exits:
            unsupported = (
                (exit_.halted and not (exit_.ret and len(exit_.ret) == 1 and exit_.ret[0][0] == "evm_return"))
                or any(k[0] in ("act", "havoc") for k in exit_.store)
                or bool(subterms(exit_.pc, "unknown"))
            )
            expanded = self.expand(exit_.pc)
            if expanded == FALSE:
                continue
            if unsupported and self._refuted(expanded):
                self.state_specialized = True
            else:
                reached.append(exit_)
        exits = reached
        if lowerer.lost or any(
            e.halted and not (e.ret and len(e.ret) == 1 and e.ret[0][0] == "evm_return") for e in exits
        ):
            return unresolved("unsupported:callee_transition")
        # Creation, raw low-level actions and unbounded writes are not guessed into summaries.
        before = {k: v for k, v in state.store.items() if k[0] != "heap"}
        if any(
            k[0] in ("act", "havoc") and (k not in before or before[k] != v) for e in exits for k, v in e.store.items()
        ):
            return unresolved("unsupported:callee_transition")
        if not exits:
            return State(FALSE, state.env, state.store, state.ret), tuple(unknown("reverted") for _ in (call[6] or ()))
        actual, expected = tuple(describe(r.type) for r in fn.returns), call[6]
        outcomes = []
        for e in exits:
            returns = e.ret or ()
            if e.halted or fallback:
                if e.halted:
                    assert returns
                    payload = returns[0][1]
                else:
                    payload = returns[0] if returns else const(b"", "bytes")
                while payload[0] == "ite":
                    if conjuncts(payload[1]) <= conjuncts(e.pc):
                        payload = payload[2]
                    elif mk_not(payload[1]) in conjuncts(e.pc):
                        payload = payload[3]
                    else:
                        break
                if raw or expected is None:
                    returned, valid = (payload,), TRUE
                else:
                    short = FALSE if request.return_size_checked is True else unknown("unsupported:short_return_buffer")
                    returned, valid = decode_buffer(payload, expected, call[8], short_guard=short)
                    if short != FALSE and short in subterms(valid, "unknown"):
                        return unresolved(str(short[1]))
                guard = mk_and([state.pc, request.input_guard, e.pc, valid, *(g for _, g in given)])
                outcomes.append(State(guard, state.env, e.store, returned))
                continue
            if len(returns) != len(actual) or (expected is not None and len(expected) > len(actual)):
                return unresolved("unsupported:callee_return_abi")
            clean = [transfer(v, t, t) for v, t in zip(returns, actual)]
            passed = (
                [transfer(v[0], a, b, strict=call[8]) for v, a, b in zip(clean, actual, expected)]
                if expected is not None
                else clean
            )
            guard = mk_and(
                [
                    state.pc,
                    request.input_guard,
                    e.pc,
                    *(g for _, g in given),
                    *(g for _, g in clean),
                    *(g for _, g in passed),
                ]
            )
            returned = tuple(v for v, _ in passed)
            if raw:
                # Only scalar encodings are represented here; preserve declared widths and
                # fixed-byte alignment rather than guessing from the computed values.
                if all(static_words(t) is not None for t in actual):
                    returned = (
                        mk(
                            "enc",
                            "abi.encode",
                            tuple(mk("conv", t[1], v) if len(t) == 2 else v for t, v in zip(actual, returned)),
                            actual,
                        ),
                    )
                else:
                    returned = (unknown("unsupported:raw_return_encoding"),)
            outcomes.append(State(guard, state.env, e.store, returned))
        combined = merge(outcomes)
        return State(combined.pc, state.env, combined.store, state.ret), combined.ret or ()
