"""Symbolic composition of explicit transaction sequences, outside the per-function engine.

This is a weakest-precondition calculation over guarded updates. It never treats a
writer's mere existence as a proof that a desired state is reachable. Different
transactions have different argument/value/origin symbols; actor equality is explicit.
"""

from __future__ import annotations

from services.logic.lower import read_store
from services.logic.model import Formula
from services.logic.terms import CALLER, ORIGIN, TRUE, Term, mk, mk_and, mk_or, replace_terms, subterms, unknown


def sequence(functions: tuple[Formula, ...], *, same_actor: bool = True, effect: int | None = None) -> Term:
    """Predicate for executing this exact sequence, ending at success or a chosen effect.

    The caller variable denotes the final actor. Earlier actors are explicit arguments
    when ``same_actor=False``. Their existence does not mean the final actor controls them.
    No claim is made about sequences that were not supplied.
    """
    if not functions:
        raise ValueError("a sequence needs at least one function")

    def frame(t: Term, index: int) -> Term:
        bindings = {a: mk("arg", f"step{index}.{a[1]}", a[2]) for a in subterms(t, "arg")}
        bindings[mk("callvalue")] = mk("arg", f"step{index}.value", "uint256")
        bindings[ORIGIN] = mk("arg", f"step{index}.origin", "address")
        if not same_actor and index < len(functions) - 1:
            bindings[CALLER] = mk("arg", f"step{index}.caller", "address")
        return replace_terms(t, bindings)

    last = functions[-1]
    result = frame(last.success if effect is None else last.effects[effect].guard, len(functions) - 1)
    for index in reversed(range(len(functions) - 1)):
        function = functions[index]
        branches = []
        for transition in function.transitions:
            store = {}
            for update in transition.updates:
                location = update.location

                def rename(v):
                    if isinstance(v, Term):
                        return frame(v, index)
                    if isinstance(v, tuple):
                        return tuple(rename(x) for x in v)
                    return v

                store[rename(location)] = frame(update.value, index)
            replacements = {}
            for kind in ("load", "rawload"):
                for load in subterms(result, kind):
                    location = (load[1], load[2], load[3]) if kind == "load" else ("raw", load[1], load[2])
                    replacements[load] = read_store(store, location)
            after = replace_terms(result, replacements)
            # An outgoing call can change storage outside the local update summary (including reentrancy).
            external = any(e.kind in ("call", "unknown") for e in function.effects)
            branches.append(
                mk_and(
                    [
                        frame(transition.guard, index),
                        after,
                        unknown("unsupported:external_transition") if external else TRUE,
                    ]
                )
            )
        result = mk_or(branches)
    return result
