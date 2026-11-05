"""Relational queries about control of a write's target and final value.

Occurrence asks whether an address can make any change. Power asks whether it can
produce an outcome that some other caller cannot produce with any arguments. Both
queries retain the original successful-execution guard; neither rates severity.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

import z3

from .cells import annotation, slot_equal, view
from .model import Effect
from .terms import CALLER, IDENTITY_KINDS, Term, contains, mk, replace_terms, subterms

if TYPE_CHECKING:
    from .solver import Translation


def write_power(effect: Effect) -> Term:
    """The exact, single-write relation, not a claim about joint multi-write control."""
    if effect.kind != "write":
        raise ValueError("write power requires a storage write")
    return mk("write_power", effect.guard, effect.target, effect.value)


def _coordinates(value: Any):
    if isinstance(value, Term):
        yield value
    elif isinstance(value, tuple):
        for part in value:
            yield from _coordinates(part)


def translate_power(term: Term, outer: Translation):
    """R(c,a) and exists d: no b realizes the same target/value under R(d,b).

    Translate one unbound relation, then alpha-rename its variables for the comparison
    call. State stays at the same block. Bindings constrain the original call only.
    Every input of the comparison call is existential inside the refusal, so it is
    allowed different arguments. Missing semantics cannot become a refusal proof.
    """
    from .solver import ADDRESS, boolean, integer

    physical = view(term[2])
    if physical is None and annotation(term[2]) is not None:
        return outer.missing(term, "write power needs a placed physical target")
    target = (physical[0], physical[2]) if physical is not None else tuple(_coordinates(term[2]))
    observed = (term[1], *target, term[3], *((physical[1],) if physical is not None else ()))
    if any(contains(t, IDENTITY_KINDS - {"caller"}) for t in observed):
        return outer.missing(term, "write power with origin or signing authority")
    if any(contains(t, frozenset({"memory_address"})) for t in observed):
        return outer.missing(term, "write power needs numeric memory addresses across executions")
    relation = outer.unbound()
    caller = relation.translate(CALLER)
    guard = boolean(relation.translate(term[1]))
    coordinates = [relation.translate(t) for t in (*target, term[3])]
    # Register scalar inputs of the slot expression without trying to compute a
    # hash. Equality of slots is a relation, not a demand for either hash value.
    if physical is not None:
        for kind in ("caller", "arg", "callvalue", "calldatasize"):
            for t in subterms(physical[1], kind):
                relation.translate(t)
    if relation.issues:
        outer.issues.extend(relation.issues)
        return outer.missing(term, "write power needs a fully modeled target/value relation")
    if any(not isinstance(v, z3.ExprRef) for v in coordinates):
        return outer.missing(term, "write power needs scalar target/value coordinates")

    def input_variable(t):
        return t[0] in {"caller", "arg", "callvalue", "calldatasize"} or (
            t[0] in {"len", "byte_chunk"} and t[1][0] == "arg" and t[1][2] in {"bytes", "string"}
        )

    if any(not input_variable(t) for t in relation.variables):
        return outer.missing(term, "write power has inputs outside the caller-controlled domain")
    variables = dict(relation.variables)
    alternative = [(v, z3.FreshConst(v.sort(), "alternative")) for v in variables.values()]
    slot_match = None
    if physical is not None:
        renamed = {}
        for i, (t, (_, fresh)) in enumerate(zip(variables, alternative)):
            # Bound synthetic operands keep assessment's no-enumeration policy.
            # The colon cannot collide with a source-language parameter name.
            type_ = t[2] if t[0] == "arg" else "address" if t[0] == "caller" else "uint256"
            name = f":power_comparison:{i}"
            replacement = mk("arg", name, type_)
            while replacement in variables or replacement in relation.bindings:
                name += ":"
                replacement = mk("arg", name, type_)
            relation.bindings[replacement] = fresh
            renamed[t] = replacement
        slot_match = boolean(relation.translate(slot_equal(physical[1], replace_terms(physical[1], renamed))))
        if relation.issues or relation.variables != variables:
            outer.issues.extend(relation.issues)
            return outer.missing(term, "write power target equality is unresolved")
    outer.assumptions.update(relation.assumptions)
    domain = z3.And(caller > 0, caller < ADDRESS)
    whole = z3.And(guard, domain, *relation.bounds)
    original = [(v, outer.translate(t)) for t, v in variables.items()]

    def rename(expression, mapping):
        return z3.substitute(expression, *mapping) if mapping else expression

    outputs = [(rename(v, original), rename(v, alternative)) for v in coordinates]
    same = [integer(current) == integer(other) for current, other in outputs]
    if slot_match is not None:
        same.append(rename(slot_match, original))
    other_caller = cast(z3.ArithRef, rename(caller, alternative))
    other_arguments = [new for old, new in alternative if not old.eq(caller)]
    achievable = z3.And(rename(whole, alternative), *same)
    # Exists b: (b = output AND P(b)) is P(output). Keep every coordinate equality
    # and input bound; repeated coordinates still constrain each other. This avoids
    # asking the quantified solver to rediscover direct argument/output equality.
    fixed = {}
    for current, other in outputs:
        if any(other.eq(arg) for arg in other_arguments):
            fixed.setdefault(other, current)
    if fixed:
        achievable = z3.simplify(rename(achievable, list(fixed.items())))
        other_arguments = [v for v in other_arguments if v not in fixed]
    if other_arguments:
        achievable = z3.Exists(other_arguments, achievable)
    refused = z3.Exists([other_caller], z3.And(other_caller > 0, other_caller < ADDRESS, z3.Not(achievable)))
    return z3.And(rename(whole, original), refused)
