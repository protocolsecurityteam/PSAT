"""Symbolic composition of explicit transaction sequences, outside the per-function engine.

This is a weakest-precondition calculation over guarded updates. It never treats a
writer's mere existence as a proof that a desired state is reachable. Different
transactions have different argument/value/origin symbols; actor equality is explicit.
"""

from __future__ import annotations

from services.logic.lower import read_store
from services.logic.model import Formula
from services.logic.terms import CALLER, ORIGIN, Term, mk, mk_and, mk_or, replace_terms, substitute, subterms, unknown


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

        def memory_scope(value):
            return substitute(
                value,
                "memory_address",
                lambda p: mk("memory_address", ("transaction", index, p[1]), memory_scope(p[2])),
            )

        return memory_scope(replace_terms(t, bindings))

    last = functions[-1]
    result = frame(last.success if effect is None else last.effects[effect].guard, len(functions) - 1)
    specialized = last.state_specialized is not False
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
                    location = tuple(load[1:]) if kind == "load" else ("raw", load[1], load[2])
                    replacements[load] = read_store(store, location)
            after = replace_terms(result, replacements)
            # An outgoing call can change storage outside the local update summary (including reentrancy).
            external = any(e.kind in ("call", "unknown") for e in function.effects)
            if external:
                after = unknown("unsupported:external_transition")
            elif transition.updates and (specialized or function.state_specialized is not False):
                # Specialized calls can use another layout for the same physical storage.
                # Name-based updates cannot establish aliases across those contexts, even
                # when only the earlier transaction delegated. Revalidation is required.
                after = unknown("unsupported:sequence_context_revalidation")
            branches.append(mk_and([frame(transition.guard, index), after]))
        result = mk_or(branches)
        specialized = specialized or function.state_specialized is not False
    return result
