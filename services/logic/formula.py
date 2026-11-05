"""Assemble per-function formulas from lowering, code linking, and symbolic call summaries."""

from __future__ import annotations

from typing import Any

from eth_utils.crypto import keccak

from .abi_values import abi_signature
from .calls import CallExecutor
from .lower import Lowerer, parameter, read_store, unwritten
from .model import Effect, Formula, Limits, Reads, Transition, Update
from .terms import CALLDATA, THIS, TRUE, Term, const, mk, mk_and, mk_cmp, mk_not, mk_or, replace_terms, unknown


def compile_function(
    contract: Any,
    function: Any,
    address: int,
    reads: Reads,
    contracts: Any,
    limits: Limits = Limits(),
    code_of=None,
    bindings=None,
    own_code=None,
    journal=None,
) -> Formula:
    linker = CallExecutor(reads, contracts, address, limits, code_of, bindings, own_code)
    linker.journal = journal
    selector = int.from_bytes(keccak(text=abi_signature(function))[:4], "big")
    runtime = own_code is not None or (code_of is not None and code_of(address) != address)
    if runtime:
        # Inventory identifies a queried selector, not the body the deployed code runs.
        # The tail can be short, dirty, or have extra bytes before any decoder executes.
        if function.is_receive:
            parameters, data, selector = (), const(b"", "bytes"), 0
        elif function.is_fallback:
            parameters = (mk("arg", "calldata", "bytes"),)
            data = parameters[0]
        else:
            parameters = (mk("arg", "calldata_tail", "bytes"),)
            data = mk("bytes_prefix", selector.to_bytes(4, "big"), parameters[0])
        exits = [linker.root(data, fallback_only=function.is_fallback)]
        frame = {THIS: const(address, "address")}
    else:
        lowerer = Lowerer(
            contract,
            this=const(address, "address"),
            code=const(address, "address"),
            call_handler=linker.handler(0),
            journal=journal,
        )
        lowerer.resolver = linker
        linker.executing.add((address, abi_signature(function)))
        try:
            lowerer.success(function)
        finally:
            linker.executing.remove((address, abi_signature(function)))
        exits = lowerer.exits
        parameters = tuple(parameter(p, i) for i, p in enumerate(function.parameters))
        frame = {
            THIS: const(address, "address"),
            mk("sig"): const(selector, "bytes4"),
            CALLDATA: mk("enc", "abi.encodeWithSelector", (const(selector, "bytes4"), *parameters)),
        }

    def linked(t: Term) -> Term:
        return linker.expand(replace_terms(t, frame))

    def location_frame(value: Any) -> Any:
        if isinstance(value, Term):
            return linked(value)
        if isinstance(value, tuple):
            return tuple(location_frame(part) for part in value)
        return value

    def guard(t: Term) -> Term:
        return linked(mk_and([t, TRUE if runtime or function.payable else mk_cmp("eq", mk("callvalue"), const(0))]))

    effects, transitions = [], []
    for exit_ in exits:
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
            bound_value = linked(value if kind in ("act", "havoc") else read_store(exit_.store, location))
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
        abi_signature(function),
        selector,
        parameters,
        mk_or([t.guard for t in transitions]),
        tuple(effects),
        tuple(transitions),
        state_specialized=linker.state_specialized or bool(journal and journal.specialized),
    )
