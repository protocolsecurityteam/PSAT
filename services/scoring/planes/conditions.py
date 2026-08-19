"""The condition plane: what a destination's own conditions say about callers."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from services.scoring.schema import coalesce_chain, entity_key

# --- what a destination's own conditions say about who may call it -----------
#
# A control edge proves AUTHORITY over an entity. It does not prove that the
# entity's own code will accept the controlled node as caller: a destination may
# pin its caller to itself, and no authority relation makes one address another.
# ``effective_functions.conditions`` carries those guards verbatim; the fold read
# none of them, so every hop walked as if the destination had no opinion.
#
# Only ONE shape is recognised as a proven disproof, and it is recognised from
# the verbatim text: a caller-or-initiator identity compared against
# ``address(this)``. Everything else — a balance check, a business predicate, an
# authorization call whose passing is exactly what the control edge witnesses —
# bears on the caller not at all and is not read as one. A recogniser that
# guessed more would turn every unparsed predicate into a refusal and delete a
# proven authority relation on the strength of a string nobody analysed.
HOP_WALKED = "walked"
HOP_NOT_DETERMINED = "not_determined"

# Whose identity the guard pins. ``msg.sender`` is the caller itself; the named
# parameters are the caller as the destination's own callee convention passes it
# on (``initiator`` in a solver callback), which is the same question one frame
# out.
#
# The recogniser is deliberately BROAD on two axes, and both are safe in exactly
# one direction:
#
#   comparator  ``!=`` and ``==`` are both read as a pin. The stored
#               ``description`` is a verbatim predicate with no polarity: the
#               same text is a require-condition in one function and a
#               revert-condition in another, so which comparator means "the
#               caller must be the destination" is not recoverable from it.
#   term        ``sender``/``caller``/``initiator`` (with or without a leading
#               underscore) are read as the caller. A parameter so named is the
#               caller under every callee convention this corpus uses, but the
#               name is the whole evidence — a parameter named ``initiator`` that
#               carried something else would be read as a caller pin here.
#
# Both over-reads land on the same side: a recognised pin only ever moves a hop
# from walked to ``not_determined``. Nothing in this module can turn a pin into a
# proven-clear, so breadth costs withheld reach and never mints reach. The
# reverse error — a pin this regex misses — is the one that would over-claim, and
# it is why the shape is not narrowed further. ``(?<![\w$])`` keeps the terms
# whole, so ``spender``/``resender`` are not caller terms.
_CALLER_TERM = r"(?:msg\.sender|_?sender|_?caller|_?initiator)"
_SELF_PIN = re.compile(
    rf"(?<![\w$])(?:{_CALLER_TERM}\s*[!=]=\s*address\(this\)|address\(this\)\s*[!=]=\s*{_CALLER_TERM}(?![\w$]))"
)

SURFACE_FUNCTION_PRINCIPAL = "function_principal_witness"
SURFACE_DESTINATION_FUNCTIONS = "destination_functions"
SURFACE_NONE = "destination_functions_not_analysed"

# On what a walked hop was walked. "No condition disproved the caller" is three
# different facts, and only the first of them is a read of any condition:
#
#   FULLY          every function consulted at the destination had its
#                  conditions extracted, so the read is complete: a guard was
#                  there to find on all of them and was found on none.
#   PARTLY         at least one permitting function had its conditions
#                  extracted and at least one consulted function did not. A
#                  guard was found on none, but the surface the answer rests on
#                  is not the surface that was consulted.
#   UNANALYSED     every function that permits the caller has ``conditions``
#                  NULL — the extraction never ran there, so "no guard" is a
#                  coverage gap wearing the shape of a clean read.
#   NO_FUNCTION    the destination has no analysed function at all; nothing was
#                  consulted, and the hop stands on the edge alone.
#
# The hop is walked in all three (refusing on an absence would let a coverage
# gap overturn a proven authority relation), so the distinction is a DISCLOSURE
# and not a bound — but a consumer cannot tell a checked hop from an unchecked
# one unless the counts are published apart.
WALKED_ON_ANALYSED_FULLY = "walked_on_fully_analysed_conditions"
WALKED_ON_ANALYSED_PARTLY = "walked_on_partly_analysed_conditions"
WALKED_ON_UNANALYSED = "walked_on_unanalysed_conditions"
WALKED_NO_FUNCTION = "walked_with_no_analysed_function"
WALKED_COVERAGE = (
    WALKED_ON_ANALYSED_FULLY,
    WALKED_ON_ANALYSED_PARTLY,
    WALKED_ON_UNANALYSED,
    WALKED_NO_FUNCTION,
)


@dataclass(frozen=True)
class DestinationFunction:
    """One function of a destination entity, and the caller guards it carries.

    ``analysed`` separates "conditions were extracted and none pins the caller"
    from "the column holds no array and nothing was extracted". Both reach
    ``caller_pinned_to_self == ()``, and reading the second as the first is the
    absence-as-a-witness move at the coverage level. The discriminator is
    ``isinstance(conditions, list)``, which is what puts a SQL null and the
    jsonb scalar null on the same side as each other and the opposite side from
    an empty array — the three-state this column's own read has to make.
    """

    function_id: int
    name: str
    caller_pinned_to_self: tuple[str, ...] = ()
    analysed: bool = False
    # This function's own selector, so a consumer can join to it on the four
    # bytes a licence names rather than on a name — 32 ``(entity, name)`` pairs
    # on the reference corpus carry more than one selector. ``None`` is a
    # function whose selector was never extracted, and it matches nothing.
    selector: str | None = None
    # Every predicate text the column holds, in stored order, verbatim and
    # UNFILTERED. ``caller_pinned_to_self`` above is the one recognised shape;
    # this is the whole population it was recognised out of, kept so a
    # disclosure can point at the evidence. Nothing here is evaluated: the text
    # carries no polarity (see ``_SELF_PIN``), so it is not readable as a
    # condition that must hold or must not.
    predicates: tuple[str, ...] = ()
    # Entries the stored array held. Larger than ``len(predicates)`` when an
    # entry carried no string ``description``, which is a shortfall in the
    # disclosure and not a predicate that is absent.
    predicate_entries_stored: int = 0


# The three states a predicate lookup can land in, kept apart because "the
# column held an empty array" is an extraction that RAN and found nothing, "the
# column holds no array" is one that never ran, and "no function of this entity
# carries that selector" is a join that missed. Collapsing any two of them would
# publish a coverage gap as a proven absence of predicates.
PREDICATES_EXTRACTED = "extracted"
PREDICATES_COLUMN_HOLDS_NO_ARRAY = "column_holds_no_array"
PREDICATES_FUNCTION_NOT_LOCATED = "destination_function_not_located"


@dataclass(frozen=True)
class DestinationPredicates:
    """The verbatim predicate texts one destination function's body carries.

    A DISCLOSURE and nothing else. The texts are stored without polarity — the
    same string is a require-condition in one function and a revert-condition in
    another — so no consumer of this can tell whether any of them must hold or
    must not, and none of them is evaluated anywhere. It exists so a reader can
    see the evidence a claim about that function was NOT made against.

    ``functions_matching`` is published because a selector is not guaranteed
    unique within an entity: an entity that folds a proxy and its implementation
    can carry two rows under one selector, and a reader is owed the fact that
    the texts below are one of them rather than the whole surface.
    """

    state: str
    function_id: int | None
    function_name: str | None
    descriptions: tuple[str, ...] | None
    entries_stored: int | None
    functions_matching: int


@dataclass(frozen=True)
class HopConditions:
    """What the destination's conditions say about one caller reaching it."""

    state: str
    basis: str
    surface: str
    functions_consulted: int
    disproving: tuple[dict[str, Any], ...] = ()
    # For a walked hop, which of the three readings above licensed it. ``None``
    # on a hop that was not walked.
    coverage: str | None = None


@dataclass
class ConditionPlane:
    """``effective_functions.conditions``, indexed for the closure walk.

    ``by_entity`` is every analysed function of an entity. ``licensed`` is the
    narrower and better-evidenced surface: the functions of that entity on which
    a given address is a RESOLVED principal, which is the only positive witness
    this plane has of what one caller may do at one destination.
    """

    by_entity: dict[str, tuple[DestinationFunction, ...]] = field(default_factory=dict)
    licensed: dict[tuple[str, str], tuple[DestinationFunction, ...]] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)

    def predicates(self, destination: str, selector: str) -> DestinationPredicates:
        """Every predicate text stored for ``destination``'s function ``selector``.

        Read-only, from ``effective_functions.conditions`` — the CANONICAL
        column, which is the one this plane loads. It is never read from
        ``function_principals.details.conditions``: that copy disagrees with the
        column on 270 of 1593 protocol-1 controller rows and nothing reconciles
        them, so a consumer that read it would be publishing a second, unowned
        extraction as this one.

        Nothing here filters, orders, evaluates or classifies. ``kind`` on the
        stored entry is not read: the label is applied to every entry the
        extractor emits — authorization guards, transfer post-conditions and
        decompiler temporaries all arrive as ``business`` — so branching on it
        would sort by a field that carries no information.
        """
        wanted = (selector or "").lower()
        # A function whose own selector was never extracted matches nothing:
        # four bytes nobody recorded do not name a function, and joining on the
        # empty string would hand back an arbitrary row's predicates.
        matching = (
            [fn for fn in self.by_entity.get(destination, ()) if fn.selector and fn.selector.lower() == wanted]
            if wanted
            else []
        )
        if not matching:
            return DestinationPredicates(PREDICATES_FUNCTION_NOT_LOCATED, None, None, None, None, 0)
        # Lowest ``function_id`` where a selector is carried twice: arbitrary,
        # deterministic, and disclosed through ``functions_matching``.
        function = min(matching, key=lambda fn: fn.function_id)
        if not function.analysed:
            return DestinationPredicates(
                PREDICATES_COLUMN_HOLDS_NO_ARRAY, function.function_id, function.name, None, None, len(matching)
            )
        return DestinationPredicates(
            PREDICATES_EXTRACTED,
            function.function_id,
            function.name,
            function.predicates,
            function.predicate_entries_stored,
            len(matching),
        )

    def hop(self, caller: str, destination: str) -> HopConditions:
        """Whether ``destination``'s own guards permit ``caller`` to act there.

        The consulted surface is the function-level witness where one exists and
        the destination's whole analysed function set otherwise. A hop is walked
        when at least one consulted function carries no guard pinning its caller
        to the destination itself; it is ``not_determined`` when every consulted
        function does. It is never published as a proven negative: the principal
        enumeration behind the licensed surface is a documented LOWER bound, so
        "no function we witnessed is callable" is not "no function is".

        A destination with no analysed function at all consults nothing, and
        nothing is not a disproof — the edge remains the witness and the
        shortfall is counted rather than converted into a refusal.

        A walked hop carries WHICH of the three coverage readings licensed it,
        because "no condition disproved this caller" over a function whose
        conditions were never extracted is not the same fact as over one whose
        were.
        """
        if caller == destination:
            return HopConditions(HOP_WALKED, "caller_is_the_destination", SURFACE_NONE, 0, coverage=WALKED_NO_FUNCTION)
        surface = self.licensed.get((destination, caller))
        surface_kind = SURFACE_FUNCTION_PRINCIPAL
        if not surface:
            surface = self.by_entity.get(destination) or ()
            surface_kind = SURFACE_DESTINATION_FUNCTIONS if surface else SURFACE_NONE
        if not surface:
            return HopConditions(
                HOP_WALKED,
                "destination_functions_not_analysed(no caller condition witnessed)",
                SURFACE_NONE,
                0,
                coverage=WALKED_NO_FUNCTION,
            )
        permitted = [fn for fn in surface if not fn.caller_pinned_to_self]
        if permitted:
            analysed = [fn for fn in permitted if fn.analysed]
            consulted_analysed = sum(1 for fn in surface if fn.analysed)
            coverage = WALKED_ON_UNANALYSED
            if analysed:
                coverage = WALKED_ON_ANALYSED_FULLY if consulted_analysed == len(surface) else WALKED_ON_ANALYSED_PARTLY
            return HopConditions(
                HOP_WALKED,
                (
                    f"caller_condition_permits({len(permitted)} of {len(surface)} consulted "
                    f"functions, {len(analysed)} of them with conditions extracted; "
                    f"{consulted_analysed} of {len(surface)} consulted functions analysed)"
                ),
                surface_kind,
                len(surface),
                coverage=coverage,
            )
        return HopConditions(
            HOP_NOT_DETERMINED,
            "caller_pinned_to_the_destination_itself_on_every_consulted_function",
            surface_kind,
            len(surface),
            tuple(
                {"function": fn.name, "function_id": fn.function_id, "conditions": list(fn.caller_pinned_to_self)}
                for fn in surface
            ),
        )


def _caller_self_pins(conditions: Any) -> tuple[str, ...]:
    """The verbatim conditions that pin this function's caller to itself."""
    if not isinstance(conditions, list):
        return ()
    out: list[str] = []
    for entry in conditions:
        text = entry.get("description") if isinstance(entry, dict) else None
        if isinstance(text, str) and _SELF_PIN.search(text):
            out.append(text)
    return tuple(out)


def _stored_predicates(conditions: Any) -> tuple[tuple[str, ...], int]:
    """Every stored predicate text, verbatim and in stored order, and the entry count.

    The whole array, unfiltered: this is the population ``_caller_self_pins``
    recognises one shape out of, kept so a disclosure can point at what was not
    read rather than assert it was not read. An entry carrying no string
    ``description`` contributes to the count and not to the texts, so the two
    disagreeing is visible instead of silent.
    """
    if not isinstance(conditions, list):
        return (), 0
    texts = [
        entry["description"]
        for entry in conditions
        if isinstance(entry, dict) and isinstance(entry.get("description"), str)
    ]
    return tuple(texts), len(conditions)


def load_condition_plane(session: Session, protocol_id: int) -> ConditionPlane:
    """The destination-side caller guards the closure walk is bounded by."""
    from db.models import Contract, EffectiveFunction, FunctionPrincipal

    plane = ConditionPlane()
    by_entity: dict[str, list[DestinationFunction]] = defaultdict(list)
    entity_of: dict[int, tuple[str, str]] = {}
    functions = (
        session.query(
            EffectiveFunction.id,
            EffectiveFunction.function_name,
            EffectiveFunction.conditions,
            EffectiveFunction.deployment_address,
            EffectiveFunction.selector,
            Contract.address,
            Contract.chain,
        )
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(EffectiveFunction.id)
        .all()
    )
    pinned_functions = 0
    analysed_functions = 0
    stored_predicates = 0
    for function_id, name, conditions, deployment, selector, address, chain in functions:
        chain_name = coalesce_chain(chain)
        key = entity_key(chain_name, deployment or address)
        pins = _caller_self_pins(conditions)
        texts, entries = _stored_predicates(conditions)
        # An ARRAY is an extraction that ran, empty or not. Anything else — a SQL
        # null, the jsonb scalar null a Python ``None`` write stores — is one
        # that never did, and the two are indistinguishable downstream unless
        # they are separated here.
        analysed = isinstance(conditions, list)
        pinned_functions += 1 if pins else 0
        analysed_functions += 1 if analysed else 0
        stored_predicates += entries
        by_entity[key].append(
            DestinationFunction(
                int(function_id),
                str(name),
                pins,
                analysed,
                (str(selector).lower() if selector else None),
                texts,
                entries,
            )
        )
        entity_of[int(function_id)] = (key, chain_name)
    plane.by_entity = {key: tuple(rows) for key, rows in sorted(by_entity.items())}

    licensed: dict[tuple[str, str], list[DestinationFunction]] = defaultdict(list)
    rows = (
        session.query(FunctionPrincipal.function_id, FunctionPrincipal.address)
        .join(EffectiveFunction, EffectiveFunction.id == FunctionPrincipal.function_id)
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(FunctionPrincipal.id)
        .all()
    )
    by_id = {fn.function_id: fn for rows_ in plane.by_entity.values() for fn in rows_}
    for function_id, address in rows:
        located = entity_of.get(int(function_id))
        if located is None:
            continue
        destination, chain_name = located
        function = by_id.get(int(function_id))
        if function is None:
            continue
        licensed[(destination, entity_key(chain_name, address))].append(function)
    plane.licensed = {key: tuple(rows_) for key, rows_ in sorted(licensed.items())}
    plane.provenance = {
        "functions": len(functions),
        "entities_with_analysed_functions": len(plane.by_entity),
        # The coverage this recogniser actually had. A function whose
        # ``conditions`` column is NULL carries no guard to find, so it can only
        # ever report "nothing disproves this caller" — which is the answer a
        # clean read gives too. Published apart, because a hop walked over
        # nothing but unextracted functions is not a checked hop.
        "functions_with_conditions_extracted": analysed_functions,
        "functions_with_no_conditions_recorded": len(functions) - analysed_functions,
        "functions_pinning_caller_to_self": pinned_functions,
        # The whole predicate population the recogniser above ran over, counted
        # so the one shape it recognises is readable against a denominator. None
        # of these is evaluated anywhere; they are retained per function only so
        # a composed magnitude can point a reader at the destination body's own
        # guards instead of asserting they were not read.
        "predicate_entries_stored": stored_predicates,
        "caller_licensed_pairs": len(plane.licensed),
        "recognised_shape": (
            "a caller-or-initiator identity compared against address(this), read verbatim from "
            "effective_functions.conditions[].description. No other predicate is read as a "
            "statement about the caller: an authorization call is the gate the control edge "
            "already witnesses, and an unparsed business predicate is not evidence against a "
            "proven authority relation"
        ),
        "recogniser_breadth": (
            "BOTH comparators (!= and ==) count as a pin, because the stored description is a "
            "verbatim predicate carrying no polarity — the same text is a require-condition in "
            "one function and a revert-condition in another. msg.sender and whole-word "
            "sender/caller/initiator (with or without a leading underscore) all count as the "
            "caller, on the name alone. Both over-reads move a hop from walked to "
            "not_determined and NOTHING here can mint a proven-clear, so the breadth costs "
            "withheld reach and never reach"
        ),
        "surface_rule": (
            "the functions of the destination on which the caller is a RESOLVED principal where "
            "such a witness exists, else the destination's whole analysed function set. A "
            "destination with no analysed function consults nothing and the hop stands on the "
            "edge rather than being converted into a refusal. The shortfall that produces is "
            "counted in provenance.reach_bounds.hop_census, which splits every walked hop into "
            "walked_on_fully_analysed_conditions, walked_on_partly_analysed_conditions, "
            "walked_on_unanalysed_conditions and walked_with_no_analysed_function. Only the "
            "first rests on a surface that was read in full; the second found a guard on none "
            "of the functions it could read and could not read all of them; the last two are "
            "hops no condition was ever read for, and they are walked on the edge alone"
        ),
    }
    return plane
