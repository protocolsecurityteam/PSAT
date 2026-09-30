"""Per-instance and per-entity contribution records and their readings."""

from __future__ import annotations

from typing import Any

from services.scoring import constants as K
from services.scoring import planes as P
from services.scoring.fold.ceilings import _PUBLISHED_CENT
from services.scoring.fold.composition import _ComposedMagnitude
from services.scoring.fold.gates import _is_number
from services.scoring.fold.readings import (
    _DISPOSED_SHEET_DOES_NOT_BOUND,
    CEILING_KIND_COMPOSED,
    CEILING_KIND_SHEET,
    SHEET_BOUND_REFUSED_BY_DISPOSITION,
    SHEET_CEILING_REFUSED_PREFIX,
)
from services.scoring.fold.types import _Instance
from services.scoring.schema import entity_key
from utils.scoring_status import (
    MAGNITUDE_STATE_PROVEN_CEILING,
    MAGNITUDE_STATE_PROVEN_EXACT,
    MAGNITUDE_STATE_PROVEN_FLOOR,
    MAGNITUDE_STATE_PROVEN_UPPER_BOUND,
    MAGNITUDE_STATES_UPPER_BOUNDING,
)


def _instance_contributions(
    instance: _Instance,
    keys: set[str],
    value_plane: P.ValuePlane,
    *,
    transitive: bool,
    composed: dict[str, _ComposedMagnitude] | None = None,
) -> tuple[
    dict[str, float],
    list[dict[str, Any]],
    dict[str, Any] | None,
    list[dict[str, Any]],
    dict[str, str],
    frozenset[str],
]:
    """One call's per-entity contributions, bounded by the one magnitude it proved.

    The fifth member maps keys whose standing figure is an upper bound to which ceiling kind it is, recorded where the
    figure is chosen so the winner's provenance is reported, not the loser's. The sixth is keys proven
    non-attribution-derived, an earned positive rather than the complement.

    A magnitude is per call, so charging it once per key multiplies it by the reach size. An ``exact`` witness is a
    budget spent across keys in deterministic order; an exhausted key is ``not_determined``, never $0. A ``floor`` says
    nothing about division, so over several keys it's ``not_determined``. At one key both leave the witness as proven.
    """
    per_key: dict[str, float] = {}
    gaps: list[dict[str, Any]] = []
    unbounded: list[dict[str, Any]] = []
    ceilings: dict[str, str] = {}
    non_attributed: set[str] = set()
    for key in sorted(keys):
        contribution, why, note, from_composed, state = _entity_contribution(
            instance, key, value_plane, transitive=transitive, composed=composed
        )
        if note is not None:
            unbounded.append(note)
        if contribution is None:
            # The raw key the walk reached, so the row names where it landed; keys added below are canonical.
            gaps.append({"function": instance.signal.function_name, "entity": key, "why": why})
            continue
        # Implementation and proxy are one priced entity; don't charge the balance twice.
        canonical = value_plane.canonical(key)
        previous = per_key.get(canonical)
        if previous is None or contribution > previous:
            per_key[canonical] = contribution
            ceilings.pop(canonical, None)
            non_attributed.discard(canonical)
        # A tie between a ceiling and a witnessed figure publishes the ceiling (the weaker claim). ``from_composed``
        # must stay true only for composed figures, since it separates the two ceiling kinds.
        kind = _ceiling_kind(from_composed, state)
        if kind is not None and contribution >= per_key[canonical]:
            ceilings[canonical] = kind
        # A tie with an attribution-derived figure revokes the grade, since the row may be publishing that number.
        if contribution >= per_key[canonical]:
            if state is not None and state not in MAGNITUDE_STATES_UPPER_BOUNDING:
                non_attributed.add(canonical)
            else:
                non_attributed.discard(canonical)

    magnitude = _witnessed_magnitude(instance)
    if magnitude is None or len(per_key) < 2:
        return (
            per_key,
            gaps,
            None,
            unbounded,
            {k: v for k, v in ceilings.items() if k in per_key},
            frozenset(non_attributed & set(per_key)),
        )

    uncapped = round(sum(sorted(per_key.values())), 6)
    # Only an exact witness apportions as a budget; floors and attribution-derived upper bounds take the refusal below.
    if instance.magnitude.state != MAGNITUDE_STATE_PROVEN_EXACT:
        for key in sorted(per_key):
            gaps.append(
                {
                    "function": instance.signal.function_name,
                    "entity": key,
                    "why": "floor_magnitude_over_multiple_keys_without_apportionment_witness(not_determined)",
                }
            )
        return (
            {},
            gaps,
            {
                "function": instance.signal.function_name,
                "capability": instance.signal.claim_id,
                "witness_state": instance.magnitude.state,
                "witnessed_usd": magnitude,
                "entities": sorted(per_key),
                "uncapped_sum_usd": uncapped,
                "published_sum_usd": None,
                "reading": (
                    "a floor proves the call moves at least this much, never how it divides "
                    "between holders; with no apportionment witness the magnitude of this call "
                    "is not_determined rather than the floor charged once per entity"
                ),
            },
            unbounded,
            {},
            frozenset(),
        )
    if uncapped <= magnitude:
        return (
            per_key,
            gaps,
            None,
            unbounded,
            {k: v for k, v in ceilings.items() if k in per_key},
            frozenset(non_attributed & set(per_key)),
        )

    capped: dict[str, float] = {}
    exhausted: list[str] = []
    remaining = magnitude
    for key in sorted(per_key):
        take = round(min(per_key[key], remaining), 6)
        remaining = round(remaining - take, 6)
        # Under half a cent publishes as $0.00, the phantom zero this refuses.
        if take < _PUBLISHED_CENT:
            exhausted.append(key)
            gaps.append(
                {
                    "function": instance.signal.function_name,
                    "entity": key,
                    "why": "call_magnitude_consumed_by_earlier_keys(share_not_determined)",
                }
            )
            continue
        capped[key] = take
    return (
        capped,
        gaps,
        {
            "function": instance.signal.function_name,
            "capability": instance.signal.claim_id,
            "witness_state": instance.magnitude.state,
            "witnessed_usd": magnitude,
            "entities": sorted(per_key),
            "entities_left_not_determined": exhausted,
            "uncapped_sum_usd": uncapped,
            "published_sum_usd": round(sum(sorted(capped.values())), 6),
            "reading": (
                "the witness bounds one call, so its keys consume it as a budget; which key "
                "the trim falls on is decided by the deterministic key order, not by evidence, "
                "and no witness apportions this magnitude between the entities"
            ),
        },
        unbounded,
        {k: v for k, v in ceilings.items() if k in capped},
        frozenset(non_attributed & set(capped)),
    )


def _ceiling_kind(from_composed: bool, state: str | None) -> str | None:
    """Which ceiling a contribution is, or ``None``.

    The branch is checked first because it's what downstream keys on.
    """
    if from_composed:
        return CEILING_KIND_COMPOSED
    if state == MAGNITUDE_STATE_PROVEN_CEILING:
        return CEILING_KIND_SHEET
    return None


def _witnessed_magnitude(instance: _Instance) -> float | None:
    raw = instance.magnitude.value
    if instance.magnitude.is_determined and _is_number(raw):
        return float(raw)  # pyright: ignore[reportArgumentType]  # _is_number narrows it
    return None


def _entity_contribution(
    instance: _Instance,
    key: str,
    value_plane: P.ValuePlane,
    *,
    transitive: bool,
    composed: dict[str, _ComposedMagnitude] | None = None,
) -> tuple[float | None, str, dict[str, Any] | None, bool, str | None]:
    """The dollars this call is proven to move against one entity, or ``None``.

    Returns whether the figure came from the composed branch (an upper bound) and the witness's magnitude state; both
    are needed because an attribution-derived figure is an upper bound whichever branch it arrived by.

    Only a magnitude witness produces a number. Substituting the entity's balance sheet is the balance-sheet-as-a-reach
    error, so the fallthrough is ``not_determined``: the row stays, value publishes null, the band falls to
    ``UNPRICED_BAND``, and confidence takes the gap.

    Floors are bounded by the sheet like exact figures; where the sheet is undetermined the floor stands and is
    disclosed as exceeding an unknown sheet. A key shared as implementation by two proxies is refused.
    """
    if key in value_plane.alias_ambiguous:
        return None, "shared_implementation_folds_onto_no_proxy(not_determined)", None, False, None
    if instance.native_only:
        # A native-only flow is valued only against the native holding; an absent native row is not_determined, never
        # $0.
        native = P.native_value_state(value_plane, key)
        if not native.is_determined:
            return None, "native_only_flow+absent_native_row(not_determined)", None, False, None
        held: float | None = float(native.value if native.value is not None else 0.0)
        # Native ETH has no delivery shape, so no disposition applies and trim equals held.
        trim: float | None = held
        basis = "native_only_flow x native_balance"
    else:
        # ``held`` is what the sheet determines; ``trim`` is what may bound a witness, which a disposed $0 sheet may not
        # (see ``ValuePlane.trimming_total``).
        held = value_plane.total(key)
        trim = value_plane.trimming_total(key)
        basis = "entity_holdings"

    magnitude = _witnessed_magnitude(instance)
    if magnitude is not None:
        state = instance.magnitude.state
        if state == MAGNITUDE_STATE_PROVEN_EXACT:
            if trim is None and held is not None:
                # Mirrors the floor branch: the sheet is determined at $0 by disposition and may not trim. The refusal
                # is named in the basis, but an exact witness gets no unbounded-figure disclosure.
                return (
                    magnitude,
                    f"witnessed_reach(exact)+{SHEET_BOUND_REFUSED_BY_DISPOSITION}",
                    {
                        "function": instance.signal.function_name,
                        "capability": instance.signal.claim_id,
                        "entity": key,
                        "witness_state": state,
                        # ``exact`` has no registered direction, so this lands under the neutral key.
                        **_unbounded_figure(state, magnitude),
                        "reading": _DISPOSED_SHEET_DOES_NOT_BOUND,
                    },
                    False,
                    state,
                )
            return (
                (min(trim, magnitude) if trim is not None else magnitude),
                f"witnessed_reach(exact) x {basis}",
                None,
                False,
                state,
            )
        if trim is not None:
            return min(trim, magnitude), f"witnessed_reach({_state_word(state)}) x {basis}", None, False, state
        if held is not None:
            # Determined but may not trim: the $0 covers what's held after disposition, not what's there to move.
            # Published under its own token because "not determined" would be false.
            return (
                magnitude,
                f"witnessed_reach({_state_word(state)})+{SHEET_BOUND_REFUSED_BY_DISPOSITION}",
                {
                    "function": instance.signal.function_name,
                    "capability": instance.signal.claim_id,
                    "entity": key,
                    "witness_state": state,
                    **_unbounded_figure(state, magnitude),
                    "reading": _DISPOSED_SHEET_DOES_NOT_BOUND,
                },
                False,
                state,
            )
        # Floors and upper bounds against an undetermined sheet are opposite claims published under opposite keys; an
        # upper bound must never appear as ``witnessed_floor_usd``.
        return (
            magnitude,
            f"witnessed_reach({_state_word(state)})+sheet_not_determined",
            {
                "function": instance.signal.function_name,
                "capability": instance.signal.claim_id,
                "entity": key,
                "witness_state": state,
                **_unbounded_figure(state, magnitude),
                "reading": _unbounded_reading(state),
            },
            False,
            state,
        )
    supplied = (composed or {}).get(value_plane.canonical(key))
    if supplied is not None:
        # The sheet bound was already applied where a sheet existed; otherwise the floor branch's disclosure applies.
        note = (
            None
            if supplied.sheet_usd is not None
            else {
                "function": instance.signal.function_name,
                "capability": instance.signal.claim_id,
                "entity": supplied.entity,
                "witness_state": supplied.witness_state,
                **_unbounded_figure(supplied.witness_state, supplied.usd),
                "reading": (
                    "a composed magnitude charged against an entity whose priced sheet is "
                    f"not_determined: {supplied.function} at {supplied.entity} is witnessed "
                    "moving this much, and no sheet was available to bound it against"
                ),
            }
        )
        return (
            supplied.usd,
            f"composed_reach_magnitude({supplied.function}) x {basis}",
            note,
            True,
            supplied.witness_state,
        )
    ceiling, ceiling_why = _sheet_ceiling(instance, key, value_plane)
    if ceiling_why is not None:
        if ceiling is not None:
            return ceiling, ceiling_why, None, False, MAGNITUDE_STATE_PROVEN_CEILING
        return None, ceiling_why, None, False, None
    if held is None:
        return (
            None,
            ("entity_value_not_determined" if not transitive else "closure_entity_value_not_determined"),
            None,
            False,
            None,
        )
    return (
        None,
        ("reach_magnitude_not_witnessed(not_determined) x " + basis + ("+closure" if transitive else "")),
        None,
        False,
        None,
    )


def _sheet_ceiling(instance: _Instance, key: str, value_plane: P.ValuePlane) -> tuple[float | None, str | None]:
    """The controlled node's own priced sheet as an upper bound, or why not.

    Returns ``(usd, why)`` when earned, ``(None, why)`` on a typed refusal, and ``(None, None)`` when the question
    doesn't arise.

    Three conjuncts: the capability is code control (replacing the code removes everything between the principal and the
    holdings; gate control leaves the node's own checks standing, and ``is_proxy`` isn't the test); the entity is the
    controlled node itself under ``canonical`` (a downstream node's code still stands); and the sheet is determined and
    complete per ``planes.ceiling_for``, whose refusals keep their own tokens.

    Anti-gaming: lowering the figure requires holding less or being non-upgradeable. Obfuscating the proxy
    fails closed: no proven capability means no row at all, charged to confidence, not a cheaper number.
    """
    if instance.signal.claim_id not in K.CODE_CONTROL_CAPABILITIES:
        return None, None
    controlled = entity_key(instance.signal.chain, instance.signal.deployment_address)
    canonical = value_plane.canonical(key)
    if canonical != value_plane.canonical(controlled):
        return None, None
    usd, reason = P.ceiling_for(value_plane, canonical)
    if reason in P.CEILING_ADMITTING_REASONS:
        return usd, f"code_control_sheet_ceiling({reason}) x entity_holdings"
    return None, f"{SHEET_CEILING_REFUSED_PREFIX}{reason})"


def _state_word(state: str) -> str:
    """The magnitude state as the one word the basis prose uses.

    Unregistered tokens print raw rather than as another state's word.
    """
    return state.removeprefix("proven_")


def _unbounded_figure(state: str, usd: float) -> dict[str, float]:
    """The disclosed figure, under the key its direction earns, so ``witnessed_floor_usd`` never carries a ceiling.

    Undirected states use a neutral key.
    """
    if state == MAGNITUDE_STATE_PROVEN_FLOOR:
        return {"witnessed_floor_usd": usd}
    if state in MAGNITUDE_STATES_UPPER_BOUNDING:
        return {"witnessed_upper_bound_usd": usd}
    return {"witnessed_usd": usd}


def _unbounded_reading(state: str) -> str:
    """How the figure came to be a bound, per state rather than per direction.

    The two upper-bounding states arrive by different proofs (a constant-amount probe crediting a whole balance vs. a
    controlled node's own sheet), so each gets its own sentence; unbranched states take the floor sentence.
    """
    if state == MAGNITUDE_STATE_PROVEN_UPPER_BOUND:
        return (
            "an attribution-derived magnitude charged against an entity whose priced sheet is "
            "not_determined: the figure is a holder's whole priced balance credited off a "
            "constant-amount probe, so it bounds this call from ABOVE and nothing here says "
            "the call moves it — and no sheet was available to bound it against this entity"
        )
    if state == MAGNITUDE_STATE_PROVEN_CEILING:
        return (
            "a magnitude typed as a sheet ceiling charged against an entity whose priced sheet "
            "is not_determined: the figure is some controlled node's own priced holdings, which "
            "bounds from ABOVE what replacing THAT node's code can move — so whichever sheet "
            "bounded it, it was not this entity's, and nothing here bounds it against this one"
        )
    return (
        "a floor witness charged against an entity whose priced sheet is "
        "not_determined: nothing here says the entity holds this much, only that "
        "the call moves at least this much somewhere, and no sheet was available "
        "to bound it against this entity"
    )
