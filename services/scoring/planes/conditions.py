"""The condition plane: what a destination's own conditions say about callers."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from services.scoring.schema import coalesce_chain, entity_key

# What a destination's own conditions say about who may call it. Authority over an entity doesn't mean its code accepts
# the controlled node as caller (a destination may pin its caller to itself). Only one shape is recognised as a
# disproof, from the verbatim text: a caller or initiator identity compared against ``address(this)``. Recognising more
# would delete proven authority relations on unanalysed strings.
HOP_WALKED = "walked"
HOP_NOT_DETERMINED = "not_determined"

# The caller terms. Deliberately broad: ``!=`` and ``==`` both count (stored text has no polarity), and
# ``sender``/``caller``/``initiator`` parameters are read as the caller by name. Over-reads only move a hop to
# ``not_determined``, never mint reach; a missed pin is what would over-claim. ``(?<![\w$])`` keeps ``spender`` out.
_CALLER_TERM = r"(?:msg\.sender|_?sender|_?caller|_?initiator)"
_SELF_PIN = re.compile(
    rf"(?<![\w$])(?:{_CALLER_TERM}\s*[!=]=\s*address\(this\)|address\(this\)\s*[!=]=\s*{_CALLER_TERM}(?![\w$]))"
)

SURFACE_FUNCTION_PRINCIPAL = "function_principal_witness"
SURFACE_DESTINATION_FUNCTIONS = "destination_functions"
SURFACE_NONE = "destination_functions_not_analysed"

# What a walked hop was walked on: every consulted function's conditions extracted (fully), some extracted (partly),
# none of the permitting ones extracted (unanalysed), or no analysed function at all. The hop is walked in every case;
# the counts are published apart so checked and unchecked hops are distinguishable.
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
    """One destination function and its caller guards.

    ``analysed`` separates "extracted, none pins the caller" from "nothing extracted" (``isinstance(conditions, list)``
    puts SQL and jsonb nulls together, apart from an empty array).
    """

    function_id: int
    name: str
    caller_pinned_to_self: tuple[str, ...] = ()
    analysed: bool = False
    # Its own selector for joins (names aren't unique); ``None`` matches nothing.
    selector: str | None = None
    # Every stored predicate text, verbatim and unfiltered, for disclosure; nothing is evaluated (no polarity).
    predicates: tuple[str, ...] = ()
    # Stored entries, including those without a string description.
    predicate_entries_stored: int = 0


# Extraction ran and found nothing, never ran, or no function has that selector: kept apart so a coverage gap isn't a
# proven absence.
PREDICATES_EXTRACTED = "extracted"
PREDICATES_COLUMN_HOLDS_NO_ARRAY = "column_holds_no_array"
PREDICATES_FUNCTION_NOT_LOCATED = "destination_function_not_located"


@dataclass(frozen=True)
class DestinationPredicates:
    """The verbatim predicate texts of one destination function.

    Disclosure only: without polarity none of them can be evaluated. ``functions_matching`` is published because a
    selector can repeat within an entity (proxy and implementation folded).
    """

    state: str
    function_id: int | None
    function_name: str | None
    descriptions: tuple[str, ...] | None
    entries_stored: int | None
    functions_matching: int


@dataclass(frozen=True)
class HopConditions:
    state: str
    basis: str
    surface: str
    functions_consulted: int
    disproving: tuple[dict[str, Any], ...] = ()
    # For a walked hop, which coverage reading licensed it; ``None`` otherwise.
    coverage: str | None = None


@dataclass
class ConditionPlane:
    """``effective_functions.conditions`` indexed for the closure walk.

    ``by_entity`` is every analysed function; ``licensed`` narrows to functions where the address is a resolved
    principal, the only positive witness of what a caller may do at a destination.
    """

    by_entity: dict[str, tuple[DestinationFunction, ...]] = field(default_factory=dict)
    licensed: dict[tuple[str, str], tuple[DestinationFunction, ...]] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)

    def predicates(self, destination: str, selector: str) -> DestinationPredicates:
        """Every predicate text stored for ``destination``'s ``selector``, from the canonical
        ``effective_functions.conditions`` column (the copy in ``function_principals.details`` disagrees on 270 of
        1593 rows). Not filtered or classified: ``kind`` is ``business`` on everything.
        """
        wanted = (selector or "").lower()
        # An unextracted selector matches nothing.
        matching = (
            [fn for fn in self.by_entity.get(destination, ()) if fn.selector and fn.selector.lower() == wanted]
            if wanted
            else []
        )
        if not matching:
            return DestinationPredicates(PREDICATES_FUNCTION_NOT_LOCATED, None, None, None, None, 0)
        # Lowest ``function_id`` when a selector repeats; disclosed via ``functions_matching``.
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
        """Whether ``destination``'s own guards permit ``caller``.

        The consulted surface is the licensed functions if any, else every analysed function. Walked if some consulted
        function doesn't pin its caller to the destination; ``not_determined`` if all do. Never a proven negative (the
        principal enumeration is a lower bound). No analysed functions is not a disproof. Walked hops carry which
        coverage reading licensed them.
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
    if not isinstance(conditions, list):
        return ()
    out: list[str] = []
    for entry in conditions:
        text = entry.get("description") if isinstance(entry, dict) else None
        if isinstance(text, str) and _SELF_PIN.search(text):
            out.append(text)
    return tuple(out)


def _stored_predicates(conditions: Any) -> tuple[tuple[str, ...], int]:
    """Every stored predicate text and the entry count; entries without a description count but add no text, so the
    mismatch is visible.
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
        # An array is an extraction that ran; SQL or jsonb null never ran.
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
        # Functions whose conditions were extracted; NULL ones can only ever report "nothing disproves", so a hop over
        # them alone isn't checked.
        "functions_with_conditions_extracted": analysed_functions,
        "functions_with_no_conditions_recorded": len(functions) - analysed_functions,
        "functions_pinning_caller_to_self": pinned_functions,
        # The predicate population the recogniser ran over, as a denominator; none is evaluated.
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
