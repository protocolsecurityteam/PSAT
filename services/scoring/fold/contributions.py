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

    The fifth member names the keys whose standing figure bounds this principal
    from ABOVE only, each mapped to WHICH ceiling it is
    (:data:`CEILING_KIND_COMPOSED` / :data:`CEILING_KIND_SHEET`). A map rather
    than a set because the two ceilings are published apart and only one of them
    spends the exposure budget, and because the kind travels with the figure that
    stands: re-deriving it later from the branch that COULD have produced a
    ceiling would report the losing candidate's provenance beside the winner's
    number. It is a subset of the returned map's keys: a key the cap below
    emptied contributes nothing and carries no bound either.

    The SIXTH names the keys whose standing figure is PROVEN not to be
    attribution-derived — an earned positive, not the complement of the fifth.
    A key is in it only where a registered magnitude state said so, so a
    contribution whose provenance this fold cannot grade appears in neither set
    and cannot help a row earn a floor. Kept beside the per-key MAX for the same
    reason ``ceilings`` is: which witness produced the figure that STANDS is only
    knowable where the figure is chosen.

    A witnessed magnitude is a per-CALL quantity: ``withdraw`` proven to move
    $28.1M moves $28.1M whichever of the keys it reached holds it. Charging it
    once per key multiplies a single proven number by the size of the reach set,
    which is the balance-sheet-as-a-reach error one level up from the one
    :func:`_entity_contribution` already refuses.

    An ``exact`` witness bounds the whole call, so its keys consume it as a
    budget: the trim falls on whichever key the deterministic order reaches
    last, an arbitrary basis that is published rather than absorbed. A key left
    with no room is ``not_determined``, never a published ``$0.00`` — an
    exhausted budget is not a measurement that the entity holds nothing.

    A ``floor`` witness bounds nothing above: it proves the call moves *at
    least* that much and says nothing about how the amount divides between two
    holders, so over more than one key the call's magnitude is
    ``not_determined`` rather than the floor charged once per key. At one key
    both rules leave the witness exactly as proven.
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
            # The RAW key the walk reached, not its canonical fold — pre-existing
            # and kept, because this row names where the walk landed and folding
            # it would report a proxy the closure never visited. The keys this
            # unit adds below are canonical, matching ``value_by_entity``.
            gaps.append({"function": instance.signal.function_name, "entity": key, "why": why})
            continue
        # An implementation and the proxy that deploys it are ONE priced entity:
        # the plane already folded the balance onto the proxy, so a row reaching
        # both keys would charge that one balance twice — once in this sum and
        # again in the exposure budget, which is keyed on these same entities.
        canonical = value_plane.canonical(key)
        previous = per_key.get(canonical)
        if previous is None or contribution > previous:
            per_key[canonical] = contribution
            ceilings.pop(canonical, None)
            # The provenance travels with the figure that replaced the previous
            # one; a stale grade left standing beside a new figure is the same
            # class of error as a stale bound.
            non_attributed.discard(canonical)
        # A tie between a ceiling and a witnessed figure publishes the ceiling's
        # bound: the weaker claim is the one both candidates support. The guard
        # is WIDENED past the composed branch rather than satisfied by having the
        # sheet branch claim ``from_composed``. That flag answers one question —
        # did this figure come from a ``_ComposedMagnitude`` — and it is what
        # separates the two kinds one line below, which is what keeps a sheet
        # ceiling out of the composed population on the published row and out of
        # the exposure skip's complement. Setting it true here would collapse
        # both of those into the composed answer.
        kind = _ceiling_kind(from_composed, state)
        if kind is not None and contribution >= per_key[canonical]:
            ceilings[canonical] = kind
        # Symmetrically weak on a tie: a figure equal to the standing one that is
        # attribution-derived REVOKES the grade, because the row may then be
        # publishing the attributed candidate's number.
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
    # Only an EXACT witness apportions as a budget. A floor and an
    # attribution-derived upper bound both fail this test and both take the
    # refusal below, for reasons that happen to converge: a floor says nothing
    # about how the amount divides, and an upper bound split across two entities
    # with no apportionment witness would attribute up to the whole bound at
    # each. Neither may join the exact side of this comparison.
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
        # A residual under half a cent publishes as $0.00 at the row's rounding,
        # which is the phantom proven-zero this branch exists to refuse — the
        # threshold is the published resolution, not exact equality with zero.
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
    """Which ceiling a contribution is, or ``None`` where it is not one.

    Two axes answer here and they are asked in order, because they are not
    mutually exclusive by construction: the composed branch reports the
    DESTINATION witness's own state, and that state could one day be a ceiling
    of some other kind. Which BRANCH supplied the number is the fact this map is
    keyed on downstream, so it is the one that decides.
    """
    if from_composed:
        return CEILING_KIND_COMPOSED
    if state == MAGNITUDE_STATE_PROVEN_CEILING:
        return CEILING_KIND_SHEET
    return None


def _witnessed_magnitude(instance: _Instance) -> float | None:
    """The one dollar figure this call's witness proved, if it proved one."""
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
    """The dollars this call is PROVEN to move against one entity, or ``None``.

    The fourth member says the figure came from the composed branch, which is
    the one branch whose number bounds this principal from ABOVE and never from
    below. It is returned rather than parsed back out of the basis string: the
    row header's bound direction turns on it, and a prose prefix is not a field.

    The FIFTH member is the magnitude state the figure came from — the witness's
    own token, handed back rather than reduced to a boolean here. Two axes read
    it and they are not the same question: the composed flag above says WHICH
    BRANCH supplied the number, and this says what the WITNESS behind it claims.
    An attribution-derived figure (a constant-amount probe crediting a holder's
    whole priced balance) bounds from above whether it arrived through the
    composed branch or through the instance's own witness, so a row cannot grade
    its direction off the branch alone. ``None`` where no figure was produced —
    there is no state to report about a contribution that does not exist.

    There is exactly one source of a number here: a magnitude witness. Reach
    membership answers "can this principal act on that entity"; it does not
    answer "how much does acting move", and the entity's balance sheet answers
    only "how much is there". Substituting the third for the second is the
    balance-sheet-as-a-reach error — an unproven quantity published as a positive
    number — and it is what charged 387 of 442 proven-reach signals a sheet
    nobody proved they could move.

    So the fallthrough is ``not_determined``, and the row does NOT disappear:
    membership stands, ``value_at_stake_usd`` publishes null, the band falls to
    ``UNPRICED_BAND`` (inv. 7's floor — a rug-shaped capability on an empty
    contract still scores), and the missing magnitude is charged to confidence's
    reach-magnitude term, which is the only place an unknown can sit without
    being published as a number.

    A FLOOR witness is bounded by the sheet exactly as an exact one is. The
    witness proves the call moves at least that much SOMEWHERE; against one
    entity it can still move no more than that entity holds, so a $28M floor
    charged against a $1k sheet publishes $28M of a protocol that has $1k — the
    same substitution one step over, with the direction of the error hidden by
    the word "floor". Where the sheet is not determined there is nothing to bound
    it with: the floor stands, and it is DISCLOSED as a figure exceeding an
    unknown sheet rather than published as if the sheet had agreed.

    ``key`` is refused outright when two proxies share it as an implementation:
    the plane folds it onto neither, and charging a shared implementation
    against a proxy picked by sort order publishes the other proxy's sheet.
    """
    if key in value_plane.alias_ambiguous:
        return None, "shared_implementation_folds_onto_no_proxy(not_determined)", None, False, None
    if instance.native_only:
        # A provably native-only flow may only be valued against the native
        # holding, and an absent native row is not_determined, never $0.
        native = P.native_value_state(value_plane, key)
        if not native.is_determined:
            return None, "native_only_flow+absent_native_row(not_determined)", None, False, None
        # Proven, and proven zero carries 0.0 — the pairing is enforced by Tri.
        held: float | None = float(native.value if native.value is not None else 0.0)
        # A native-only flow is valued against the native holding, which no
        # delivery-shape disposition touches — native ETH emits no Transfer log
        # and has no delivery shape to read — so the trimming figure IS the held
        # one on this arm.
        trim: float | None = held
        basis = "native_only_flow x native_balance"
    else:
        # TWO figures, and they answer two questions. ``held`` is what the sheet
        # DETERMINES the entity holds and is what the fallthrough below reports
        # on; ``trim`` is what the sheet may BOUND A WITNESS with, which a
        # disposed sheet's determined $0 may not do (``ValuePlane.trimming_total``
        # states why). Reading one off the other would either trim a witnessed
        # magnitude to a false zero or publish a determined sheet as unknown.
        held = value_plane.total(key)
        trim = value_plane.trimming_total(key)
        basis = "entity_holdings"

    magnitude = _witnessed_magnitude(instance)
    if magnitude is not None:
        state = instance.magnitude.state
        if state == MAGNITUDE_STATE_PROVEN_EXACT:
            if trim is None and held is not None:
                # SYMMETRY WITH THE FLOOR BRANCH BELOW, and for the same reason:
                # the sheet IS determined, at $0, by delivery-shape disposition,
                # and may not trim. What differs is only the disclosure this
                # state OWES — an exact witness publishes the dollars the call
                # moves, not a figure the sheet failed to bound — so the refusal
                # is named in the basis and carried as a reading, while the
                # unbounded-figure keys stay off it. Without this the basis said
                # "x entity_holdings" over a sheet that bounded nothing.
                return (
                    magnitude,
                    f"witnessed_reach(exact)+{SHEET_BOUND_REFUSED_BY_DISPOSITION}",
                    {
                        "function": instance.signal.function_name,
                        "capability": instance.signal.claim_id,
                        "entity": key,
                        "witness_state": state,
                        # ``exact`` has no registered direction, so the figure
                        # lands under the key that claims neither — the same
                        # registry the siblings read, never a hand-written key.
                        **_unbounded_figure(state, magnitude),
                        "reading": _DISPOSED_SHEET_DOES_NOT_BOUND,
                    },
                    False,
                    state,
                )
            # The witness bounds what this call moves; the entity's sheet bounds
            # what is there to move. Neither alone is the answer, and the sheet
            # alone is the balance-sheet-as-a-reach error.
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
            # The sheet IS determined and still may not trim. Its own state says
            # why: every reading on it arrived as a mass distribution, over an
            # asset list that is not proven whole, so the $0 bounds what the
            # entity HOLDS as a determined figure and says nothing about what is
            # there to MOVE — the disposed assets are still held, and delivery
            # shape is not a claim about worth. Published under its own token
            # rather than the not_determined one below, because "the sheet is
            # not determined" is FALSE here and a reader acts on that word.
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
        # NEITHER a floor NOR an upper bound may be charged against an entity
        # whose priced sheet is not_determined without saying so. The arithmetic
        # is the same on both — nothing was available to bound the figure with —
        # but the two disclosures are opposite claims and are published under
        # opposite names: a floor says the call moves AT LEAST this much
        # somewhere, an upper bound says the whole figure is a ceiling that no
        # witness says the call reaches. Writing an upper bound under
        # ``witnessed_floor_usd`` would republish it as the one thing it is not.
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
        # The dollars are the DESTINATION function's witness, composed along a
        # path every hop of which carries an act-as witness. The bound against
        # this entity's sheet was already applied where a sheet existed; where it
        # did not, the same disclosure the floor branch owes is owed here.
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
        # ``_sheet_ceiling`` pairs a figure with an ADMITTING reason and ``None``
        # with a refusal, so the two branches here are its two answers and not a
        # figure test standing in for one.
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

    ``(usd, why)``. A number with its basis where the branch is EARNED; ``None``
    with a typed refusal where the capability qualifies and the sheet does not;
    ``(None, None)`` where the question does not arise at all, which is the state
    the fall-through below this branch is written for and must not be confused
    with a refusal.

    Three conjuncts, and each of them is a different claim.

    The CAPABILITY must be code control. Replacing what a node does removes the
    node's own code from between the principal and what the node holds, and then
    "how much can they move" has an answer nothing further has to witness: at
    most what is there. Gate control has no such argument — the vault's own share
    math, caps and caller conditions are all still standing and none of them has
    been examined — so it stays where Phase 6 left it. The test is on the
    capability and never on ``is_proxy``: ``exec.arbitrary`` on a contract that
    was never a proxy dictates that contract's behaviour just as completely.

    The ENTITY must be the controlled node itself — the deployment the capability
    was witnessed on, compared under ``canonical`` so an implementation and its
    proxy are the one entity they are. Code control expands over the closure, but
    a downstream node that the controlled one merely governs is the gate-control
    situation one level down: THAT node's code is still standing. Charging its
    sheet here would restore the balance-sheet-as-a-reach error under a new name,
    over a much larger population than the one this branch exists to price.

    The SHEET must be determined AND COMPLETE, which is ``planes.ceiling_for``'s
    question and not this one's. Its two admitting reasons both produce a figure
    — a proven zero is a witness and publishes $0 rather than not_determined —
    and its five refusals are published under their own tokens, because "no
    balance was ever observed here", "the price lookup never answered" and "the
    asset list was read at its page cap" are the work of three different
    pipelines and a reader who cannot tell them apart cannot act on any of them.

    The claim's own provenness is not re-tested here: :func:`_row_value` admits an
    instance only where ``value_state`` is ``proven_reach``, so an unproven claim
    never reaches this function with an entity to charge.

    ANTI-GAMING (inv. 13), because a branch that reads a protocol's own balance
    sheet invites the question. Both conjuncts are expensive to move and neither
    is movable by presentation: to lower the figure a protocol must hold less, or
    be genuinely non-upgradeable, and both of those are real facts about it
    rather than facts about how it is described. The residual vector is the third
    thing — obfuscating the proxy pattern so the upgrade capability cannot be
    PROVEN — and it is named rather than claimed away. It fails closed the way
    every capability detection in this pipeline fails closed: an unproven
    capability produces no finding, so it produces NO ceiling row at all, not a
    smaller one. What such a protocol buys is the absence of the row, which is
    charged to confidence as an unanswered question, and not a cheaper number
    standing in the document where the honest one would have been.
    """
    if instance.signal.claim_id not in K.CODE_CONTROL_CAPABILITIES:
        return None, None
    controlled = entity_key(instance.signal.chain, instance.signal.deployment_address)
    canonical = value_plane.canonical(key)
    if canonical != value_plane.canonical(controlled):
        return None, None
    usd, reason = P.ceiling_for(value_plane, canonical)
    if reason in P.CEILING_ADMITTING_REASONS:
        # ``ceiling_for`` pairs a number with exactly the two admitting reasons,
        # so this is the branch where ``usd`` is one — asserted by returning it
        # rather than by a comment, since a ``None`` here would publish the
        # refusal path's shape under the admission's name.
        return usd, f"code_control_sheet_ceiling({reason}) x entity_holdings"
    return None, f"{SHEET_CEILING_REFUSED_PREFIX}{reason})"


def _state_word(state: str) -> str:
    """The magnitude state as the one word the basis prose uses.

    Derived from the token rather than written per branch, so a state that joins
    the vocabulary cannot silently keep publishing another state's word. An
    unregistered token prints as itself: a reader who sees a raw token knows the
    prose was not written for it, which is better than seeing "floor".
    """
    return state.removeprefix("proven_")


def _unbounded_figure(state: str, usd: float) -> dict[str, float]:
    """The disclosed figure, under the name its DIRECTION earns.

    A floor and an upper bound charged against an unpriced sheet are the same
    arithmetic and opposite claims, so they are published under different keys —
    a consumer reading ``witnessed_floor_usd`` must never pick up a ceiling. A
    state with no registered direction publishes the figure under a name that
    claims neither.
    """
    if state == MAGNITUDE_STATE_PROVEN_FLOOR:
        return {"witnessed_floor_usd": usd}
    if state in MAGNITUDE_STATES_UPPER_BOUNDING:
        return {"witnessed_upper_bound_usd": usd}
    return {"witnessed_usd": usd}


def _unbounded_reading(state: str) -> str:
    """How the figure came to be a bound, in the terms of its OWN provenance.

    Branched per state and not per direction, which is why it does not reuse the
    direction registry the way ``_unbounded_figure`` above does. The key names
    where the figure sits; this names how it got there, and the two
    upper-bounding states got there by different proofs — a constant-amount
    probe crediting a holder's whole balance, and a controlled node's own priced
    sheet. One sentence written for the first is a false account of the second,
    so each state says what is true of itself. A state with no branch of its own
    takes the floor sentence, which is where every witnessed non-exact figure
    landed before any direction was registered; that is inherited behaviour, and
    no state reaches it today.

    The one call site is ``_entity_contribution``'s branch for a witnessed figure
    charged against an entity whose OWN sheet is not_determined, so what it reads
    is a state that travelled to this entity from somewhere else. A sheet ceiling
    admitted at its own node never arrives here — the admission rule requires
    that node's sheet to be determined, which is the branch above this one — and
    the ceiling's own disclosure is not written here at all: it is written by the
    ceiling branch, ahead of the fallthrough, from its own reading registry. This
    arm exists so that a ceiling state which does reach this call site is
    described by its provenance rather than by the attribution path's.
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
