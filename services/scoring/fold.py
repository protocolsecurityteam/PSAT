"""Layer 2 — the whole-protocol grade fold. Pure, read-only, deterministic.

The fold is a recompute, never an accumulator. Three facts make a running total
wrong: value is MAX per (entity, asset) so two contracts reaching one vault must
charge it once; principal units are cross-contract and get RE-KEYED when a later
contract reveals an owner overlap; and which finding subsumes which is only
decidable with the whole finding set present.

Its population is the signal plane and nothing else — read through the one
pinned, totally ordered query — plus the resolution planes in
:mod:`services.scoring.planes`, which is where a reference becomes a unit, a
dollar or a breadth floor.

THE ROOT RULE
-------------
**Never substitute an available field for an unread one.** Every ``x or y`` on a
nullable or three-state expression is that substitution written as an idiom: an
owner set that did not resolve is not the threshold, an unread delay is not zero,
an unpriced entity is not ``$0.00``, and a principal address is not its own owner
set unless the principal IS a key. Where a witness is missing the answer is the
uncredited rung, an explicit ``None``, or a withheld row — chosen so the mistake
costs a credit rather than fabricating one. Every remaining fallback in this
module is guarded by a proof that the substituted value IS the fact.

Every arithmetic branch fails closed. A signal whose severity was not proven is
not scored; a value that could not be priced falls to the unpriced branch rather
than to zero; a malformed gate envelope withholds its own row rather than
raising out of the whole fold.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, cast

from sqlalchemy.orm import Session

from services.scoring import constants as K
from services.scoring import planes as P
from services.scoring.population import current_signals_with_faults
from services.scoring.schema import (
    NOT_DETERMINED,
    FunctionSignal,
    ScoreDocument,
    Tri,
    entity_key,
)
from utils import execution_record as EX
from utils.execution_record import PROVING_EXECUTION_KEY
from utils.scoring_status import (
    GRADE_FAULT_DEGRADED,
    GRADE_STATE_COMPUTED,
    GRADE_STATE_NOT_DETERMINED,
    MAGNITUDE_STATE_PROVEN_CEILING,
    MAGNITUDE_STATE_PROVEN_EXACT,
    MAGNITUDE_STATE_PROVEN_FLOOR,
    MAGNITUDE_STATE_PROVEN_UPPER_BOUND,
    MAGNITUDE_STATES_UPPER_BOUNDING,
    MODEL_VERSION,
    OPENNESS_NOT_DETERMINED,
    OPENNESS_OPEN,
    PRINCIPAL_STATE_ENUMERATED,
    PRINCIPAL_STATE_NONE_REQUIRED,
    PRINCIPAL_STATE_NOT_DETERMINED,
    SCORE_TRIGGER_MANUAL,
    SEVERITY_STATE_PROVEN,
    VALUE_STATE_PROVEN_NO_REACH,
    VALUE_STATE_PROVEN_REACH,
)

if TYPE_CHECKING:
    from services.scoring.distill import ProtocolUniverse

ANYONE = "anyone"

# The closed vocabulary of every gate the fold reads: gate name → the proven
# state tokens that license its positive branch. ``gate_inputs`` is free-form
# JSONB with no CHECK behind it, so a reader that branches on "is not
# not_determined" treats a WITHHELD envelope (say ``not_earned``) as the earned
# one. Branching on the exact token is what makes the two different facts again.
GATE_PROVEN_TOKENS: dict[str, tuple[str, ...]] = {
    "exact_empty_credit": ("earned",),
    "latch_witness": ("witnessed",),
    # F4: ``proven_upper_bound`` is the ATTRIBUTION path's own state and MUST be
    # listed. ``_malformed_gates`` withholds any row whose gate state is neither
    # ``not_determined`` nor a member here, and ``_gate`` degrades it — so
    # omitting it would take every attribution-derived magnitude out at once,
    # which is a number movement dressed as a vocabulary omission.
    #
    # ``proven_ceiling`` (``scoring_status.MAGNITUDE_STATES_UPPER_BOUNDING``) is
    # ABSENT ON PURPOSE, and its absence takes no population out. This list
    # allow-lists states a DISTILLED signal may carry on its own
    # ``reach_magnitude_usd`` gate; a sheet ceiling is derived inside the fold
    # from the ``ValuePlane`` at the moment a code-control capability is priced
    # against the node it controls, so no signal ever presents it here and the
    # F4 hazard cannot apply to it. Should a distiller ever stamp the state onto
    # a gate, this is the line that must gain it — the omission is a scope
    # ruling, not an oversight.
    "reach_magnitude_usd": (
        MAGNITUDE_STATE_PROVEN_EXACT,
        MAGNITUDE_STATE_PROVEN_FLOOR,
        MAGNITUDE_STATE_PROVEN_UPPER_BOUND,
    ),
    # Both states are PROVEN: the distiller always performed the lookup, and the
    # earned negative carries the typed reason there is no record. The
    # execution's own three-state answer lives inside the payload — see
    # ``utils.execution_record``.
    PROVING_EXECUTION_KEY: EX.GATE_STATES,
    "token_identity": ("proven",),
    "asset_class": ("proven",),
    "input_seeded": ("proven",),
    "contract_balance_seeded": ("proven",),
    "amount_capped_by_balance": ("proven",),
    "asset_identity": ("resolved",),
    "pause_effective": ("proven",),
    "freeze_recovery_principals": ("enumerated",),
    "freeze_coverage_fraction": ("observed_blast_radius",),
    "destination_basis": ("basis",),
}

# Gates whose payload enters arithmetic. Validated as a real, finite number at
# READ as well as at construction: a string "1e12" compares and multiplies just
# fine in Python and would charge $1T off an untyped payload.
NUMERIC_GATES = frozenset({"reach_magnitude_usd"})

# Every gate's payload SHAPE, checked before any consumer walks it. ``gate_inputs``
# is free-form JSONB, so a list the fold iterates as dicts can arrive as a list of
# ints; without this the walk raises out of ``compute_protocol_score`` and one bad
# payload on one function silently costs the whole protocol its score.
GATE_PAYLOAD_SHAPES: dict[str, str] = {
    "exact_empty_credit": "object",
    "latch_witness": "object",
    "asset_identity": "object",
    "reach_magnitude_usd": "number",
    PROVING_EXECUTION_KEY: "object",
    "token_identity": "bool",
    "input_seeded": "bool",
    "contract_balance_seeded": "bool",
    "amount_capped_by_balance": "bool",
    "asset_class": "string",
    "destination_basis": "string",
    "pause_effective": "bool",
    "freeze_coverage_fraction": "string_list",
    "freeze_recovery_principals": "principal_ref_list",
}

# The gates the fold WILL read for a given claim. A signal missing one of them is
# a distiller bug, and it withholds its own row: reading a gate that was never
# written would put a default where a witness belongs, and raising would let one
# malformed row take the whole protocol's grade down with it.
REQUIRED_GATES = ("exact_empty_credit", "latch_witness", "reach_magnitude_usd")
REQUIRED_GATES_BY_CLAIM: dict[str, tuple[str, ...]] = {
    "flow.out": ("token_identity", "asset_class", "asset_identity"),
    "pause.set": ("freeze_recovery_principals",),
}

SINGLE_ASSET_CLASSES = frozenset({"erc20_only", "mixed"})

# The composition rule's arms, as a closed vocabulary. Named here so the entry
# can PUBLISH which one it took rather than leave a reader to infer it from
# whether a figure is present — and so an unrecognised route has a token of its
# own to fail to. There is no default arm and no ``else`` that republishes: a
# candidate whose route earns none of the typed outcomes is ``not_determined``
# and its figure is withheld.
ARM_GATE_ONLY = "gate_only"
ARM_WITHHELD = "withheld"
ARM_REPUBLISHED_DIRECT = "republished_direct"
ARM_NOT_DETERMINED = NOT_DETERMINED
COMPOSITION_ARMS = (ARM_GATE_ONLY, ARM_WITHHELD, ARM_REPUBLISHED_DIRECT, ARM_NOT_DETERMINED)

# True on every withheld entry whatever arm withheld it: the candidate reached
# the rule at all, which is what a destination magnitude plus a witnessed reach
# buys, and the figure is gone anyway.
_WITHHELD_OPENING = (
    "the destination carries a flow.out magnitude and this principal is witnessed able to reach "
    "it, and the DOLLARS are still withheld"
)

# One middle per arm, because the three arms withhold for three different
# reasons and a single sentence for all of them is false on at least one. The
# transport-fault arm is the sharp case: :func:`_admit_composed` computes the
# route classification and the deletability verdict BEFORE the fault branch, so
# a faulted entry can publish ``authority_deletability.state == "deletable"`` —
# and a sentence saying "neither answered in favour of the figure" is then false
# beside the block that disproves it. Naming the arm's own reason is the fix;
# softening the sentence until it is true everywhere would trade a false claim
# for an unfalsifiable one.
_WITHHELD_ARM_READINGS = {
    ARM_WITHHELD: (
        ". The figure's own execution could not be READ at all: proving_execution above carries "
        "the typed transport fault that stopped it, so there is no proven call here for "
        "route_comparison to compare this entry's claimed route against, and it reports that "
        "rather than a match. The act_as_chain is published above in full — it is the act-as "
        "plane's witness and is established without any transcript — and whether the proof was "
        "admitted for THIS caller is answered separately under gate_claim, which has no recorded "
        "caller to read. route_classification and authority_deletability were both computed "
        "before this arm was reached and are published above unchanged: a deletability licence "
        "standing beside this refusal does NOT release it, because an execution that could not "
        "be read is not a proven call to republish"
    ),
    ARM_GATE_ONLY: (
        ". What was proven is the call recorded under proving_execution; what this entry claims "
        "is a route through an intermediate, and the two are compared under route_comparison "
        "rather than assumed equal. The gate claim survives that difference — an authorization "
        "check reads msg.sender and msg.sig and no ARGUMENT, so a route the proof did not take "
        "says nothing about it — and the act_as_chain above is published in full. Whether the "
        "proof was admitted for THIS caller is a separate question and is answered separately, "
        "under gate_claim: a different caller is not covered by that argument, because "
        "msg.sender is what the check reads. The MAGNITUDE does not survive it: "
        "route_classification witnesses the traversed body acting on what the destination call "
        "carries, under the typed finding withheld_reason names, and authority_deletability did "
        "not prove this principal could have issued the proven call itself. The refusal is the "
        "route's; what the join answered — a proven negative or an undetermined one — is "
        "published beside it either way and is not collapsed into it"
    ),
    ARM_NOT_DETERMINED: (
        ". What was proven is the call recorded under proving_execution; what this entry claims "
        "is a route through an intermediate, and the two are compared under route_comparison "
        "rather than assumed equal. The gate claim survives that difference — an authorization "
        "check reads msg.sender and msg.sig and no ARGUMENT, so a route the proof did not take "
        "says nothing about it — and the act_as_chain above is published in full. Whether the "
        "proof was admitted for THIS caller is a separate question and is answered separately, "
        "under gate_claim: a different caller is not covered by that argument, because "
        "msg.sender is what the check reads. The MAGNITUDE is refused by neither question and "
        "carried by neither: route_classification earned no typed finding about the traversed "
        "body and stands at not_determined, and authority_deletability did not prove this "
        "principal could have issued the proven call itself. There is no fourth arm that "
        "publishes on an unanswered route"
    ),
}

# A field-description: it says what a consumer may not conclude and asserts
# nothing about the entry carrying it.
_WITHHELD_CLOSING = (
    ". This is a REFUSAL and not a zero: nothing here says the principal moves nothing, only "
    "that what it moves is not determined by this evidence"
)


@dataclass
class _Instance:
    """One signal's contribution to one (unit, capability, weakness) row."""

    signal: FunctionSignal
    severity: float
    severity_basis: tuple[str, ...]
    entity_keys: tuple[str, ...]
    magnitude: Tri[float]
    value_bound: str
    pricing_blocked: str | None
    native_only: bool
    asset_identity_undecidable: bool
    # The principal this instance was witnessed under. A merged unit's row folds
    # instances from several members, and without this the row cannot say WHICH
    # member is proven to reach a given entity (inv.5 is the weakest path to that
    # entity, not the weakest member of the unit).
    principal_address: str = ""


@dataclass
class _Row:
    unit: str
    capability: str
    path: str
    weakness: float = 0.0
    weakest_label: str = ""
    principal_kind: str = ""
    weakest_address: str = ""
    principal_addresses: set[str] = field(default_factory=set)
    # Per contributing member address, the ``(weakness, label, kind)`` IT earned.
    # The row-level ``weakness`` is the max over these, which is only the right
    # price for an entity every member reaches; ``_aggregate`` re-attributes the
    # rest from this map.
    member_gate: dict[str, tuple[float, str, str]] = field(default_factory=dict)
    # The burn-sentinel admission rule's own count, and the instances it emptied
    # outright — an admission rule publishes what it refused (§3.1 pt 5).
    zero_reach_keys_refused: int = 0
    zero_reach_stripped: list[dict[str, Any]] = field(default_factory=list)
    instances: list[_Instance] = field(default_factory=list)
    seeds: set[str] = field(default_factory=set)
    tiers: set[str] = field(default_factory=set)
    notes: set[str] = field(default_factory=set)
    citations: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class _WalkedHop:
    """One hop the closure walk admitted, and what it licensed at its far end."""

    caller: str
    destination: str
    licensed: frozenset[P.LicensedFunction]


# How much a magnitude witness state CLAIMS, lowest first. Read only to settle a
# tie between two candidates at the same figure: the state published is the
# least-claiming of them, because an exactness that one tied candidate does not
# support would be exactness minted by whichever candidate the iteration reached
# first.
# ``proven_upper_bound`` ranks WITH ``proven_exact`` rather than below it, and
# that is a deliberate hold rather than a judgement about how much it claims. The
# rank exists only to settle a tie between two candidates at the same figure, so
# moving it moves which candidate is published — a number-shaped change that
# belongs with the composition ruling, not with the relabel. Ranking it apart
# from the map (``_WITNESS_STATE_UNRANKED``) would be worse than either: that
# slot is reserved for states this fold cannot rank, and a KNOWN state parked
# there launders a known fact into the unknown bucket.
_WITNESS_STATE_CLAIM = {
    MAGNITUDE_STATE_PROVEN_FLOOR: 1,
    MAGNITUDE_STATE_PROVEN_EXACT: 2,
    MAGNITUDE_STATE_PROVEN_UPPER_BOUND: 2,
}
# A state this map cannot rank is ranked so that it can never WIN a tie. Sorting
# it with the weakest would be the fail-open: "we do not know what this claims"
# would beat a state proven to claim little, and an unrankable string would be
# published in preference to a witness. Losing every tie means it is published
# only where it is the sole candidate — where it is the only thing there is to
# publish and no comparison was made.
_WITNESS_STATE_UNRANKED = len(_WITNESS_STATE_CLAIM) + 1

# Where the published dollars came from, one sentence per value of
# ``bounded_by``. A single sentence for both is a claim about the row and it is
# FALSE on one of them: the entry's figure is the MIN of the destination
# function's own flow.out witness and the destination entity's balance sheet, so
# on every entry the sheet won, "not the destination's balance sheet" names as
# excluded the very thing that capped the figure — and ``destination_sheet_usd``
# beside it equals ``published_usd``, so the document contradicts itself in two
# adjacent keys. Neither sentence asserts which ceiling is the smaller in
# general; each says which one bound THIS figure and points at the other.
_BOUNDED_BY_WITNESS = "flow.out witness"
_BOUNDED_BY_SHEET = "destination sheet"

_COMPOSED_SOURCE_READINGS = {
    _BOUNDED_BY_WITNESS: (
        "the dollars are the DESTINATION function's own flow.out witness, and not this row's "
        "balance sheet. The destination entity's own sheet did not bind them here — bounded_by "
        "beside destination_sheet_usd and sheet_not_determined says which of the two ceilings "
        "did and what the other one was"
    ),
    _BOUNDED_BY_SHEET: (
        "the dollars are the DESTINATION entity's own BALANCE SHEET, and not this row's. The "
        "sheet is BELOW that function's flow.out witness here and is what capped the figure — "
        "bounded_by beside destination_sheet_usd and flow_out_witness.usd says which of the two "
        "ceilings did and what the other one was"
    ),
}

# The publication rounding this document applies to dollar figures. Cents are
# the unit a reader reads a balance in, and that is all this rounding is for —
# so, as in the value plane's own presentation rounding (``planes._round_presented``,
# same rule at six decimals), it is not allowed to change what a figure PROVES.
# A proven bound of $0.00156 published as $0.00 stops being a number and starts
# being "nothing at stake", which is a different claim about the entity than the
# one that was measured — and on a ceiling it is the claim that reads as safety.
# Below the rounding's own resolution the unrounded figure is therefore what
# stands.
_PUBLISHED_DECIMALS = 2


def _round_published(value: float) -> float:
    """Round to cents for publication, never onto zero."""
    rounded = round(value, _PUBLISHED_DECIMALS)
    return rounded if rounded != 0.0 or value == 0.0 else value


# The token a figure carries where a sheet EXISTS, is determined, and still may
# not bound a witness. One token, used at both trim sites and published on both
# surfaces, so the two cannot drift into describing the same fact differently.
SHEET_BOUND_REFUSED_BY_DISPOSITION = "sheet_determined_by_disposition_does_not_bound"

# And what that token means, in the one sentence both surfaces publish. It says
# what the sheet DOES determine as well as what it does not, because the
# alternative reading — "the sheet is not determined" — is false here and is the
# word a reader would otherwise act on.
_DISPOSED_SHEET_DOES_NOT_BOUND = (
    "a witnessed magnitude charged against an entity whose sheet IS determined, at $0, by "
    "delivery-shape disposition: every reading on it arrived only in transactions carrying at "
    "least the published fan-out threshold of same-token transfer LOGS. That determination is "
    "over the "
    "readings observed, on an asset list that is NOT proven whole, and it is a claim about how "
    "the holdings arrived and never about what they are worth — two of the tokens measured into "
    "that state on this corpus are real ones. So the $0 bounds what the entity HOLDS and not "
    "what is there to MOVE, the sheet does not trim this figure, and the witness stands alone"
)

# The other thing a trim owes, and the one the entry used to leave unsaid: the
# sheet trimmed the figure and is NOT proven to cover everything the destination
# holds. A priced sheet that does not cover its node is a floor over what was
# priced, so ``min(witness, sheet)`` against it publishes a number SMALLER than
# the witness on a bound nothing established — an under-report of what the call
# reaches, dressed as a tighter ceiling. The figure still stands (it is the
# honest min of what is known) and the entry stops calling it an at-most. The
# sentence POINTS at the fields the direction is derived from rather than
# restating the shortfall, which is derived once and published there.
_TRIMMED_TO_AN_UNPROVEN_CEILING = (
    "The sheet that capped this figure is NOT proven to cover everything observed at that "
    "destination, so the cap is not a proven at-most and the published figure may sit below "
    "what the call reaches: destination_sheet_bound_direction says which of the two it is, and "
    "destination_sheet_bound_direction_basis enumerates, off the destination's own coverage, "
    "the conjunct(s) of that proof this sheet fails"
)

# --- the two ceilings, kept apart ------------------------------------------
# A row's figure can be an upper bound for two unrelated reasons, and the
# document may not spell them the same. The COMPOSED extraction ceiling is a
# destination function's own flow.out witness, reused across a gate the
# principal is witnessed able to make the seized node use; the SHEET ceiling is
# the controlled node's own priced holdings, admitted because replacing that
# node's code leaves nothing of that node's between the principal and what it
# holds. They differ in provenance, in what could tighten them, and — the reason
# the distinction is load-bearing rather than cosmetic — in whether they spend
# the exposure budget: an extraction ceiling is a witnessed move and charges it,
# a sheet ceiling is an at-most on a move nobody witnessed and does not.
CEILING_KIND_COMPOSED = "composed_extraction"
CEILING_KIND_SHEET = "sheet"

# The refusal token a code-control call writes into a row's ``why`` vocabulary
# when the capability qualified for a sheet ceiling and the SHEET did not. One
# constant because it is written in one place and read back in another — the
# document-level rollup counts these refusals off the published rows — and two
# copies of the spelling would drift apart silently, publishing a census of
# zero refusals over a corpus full of them.
SHEET_CEILING_REFUSED_PREFIX = "code_control_sheet_ceiling_refused("

# The reasons a sheet ceiling was REFUSED: the closed ceiling vocabulary minus
# the two that admit. DERIVED from the plane's own tuples rather than listed
# here, because a fifth refusal added there and not here would be published by
# the fold and counted by nothing — the census would report it as absent, which
# is the one thing a census of refusals must never do.
CEILING_REFUSAL_REASONS = tuple(r for r in P.CEILING_REASONS if r not in P.CEILING_ADMITTING_REASONS)

# Where a sheet ceiling's dollars came from, keyed on the admitting reason AND
# on whether the sheet covers everything the entity holds. Its own registry and
# not a third key in ``_COMPOSED_SOURCE_READINGS`` above: that map is keyed on
# ``_ComposedMagnitude.bounded_by`` and a sheet ceiling constructs no
# ``_ComposedMagnitude``, so an entry there is one nothing can carry.
#
# The second axis is the one that was got wrong first. The three
# ADMITS are different proofs — a priced sheet bounds at a number that was
# observed, a proven-empty one bounds at zero because every quantity on it was
# witnessed zero — and a single sentence would have to call one of them the
# other. The COVERAGE axis is not a shade of either: ``SHEET_PRICED`` means the
# total is a FLOOR over what was priced (``planes.ValuePlane.sheet_state``), so
# on an entity holding assets nobody priced the figure is not an at-most on the
# move at all. It is an at-most on the PRICED PORTION, and saying otherwise
# claims a bound over holdings this fold never observed. Every ADMITTED entry on
# the reference corpus takes the partial arm — those entities hold assets nobody
# priced — while the PROVEN-EMPTY ones take the full-coverage arm, which is the
# only shape in which coverage is trivially whole: a sheet whose every quantity
# is witnessed zero has nothing left over to be uncovered.
#
# The AIRDROP-DETERMINED admit carries BOTH arms, and its partial one is the
# COMMON case rather than an unreachable combination. Coverage there is earned,
# not implied: a disposition says an asset's contribution is nil and says
# nothing about whether the LIST is whole, so a disposed sheet clears
# ``_asset_coverage["complete"]`` only where the list is separately proven — and
# the below-resolution readings that sit beside the disposed ones on this corpus
# are not disposed and not priced, which is exactly the partial arm.
_CEILING_SOURCE_READINGS = {
    (P.CEILING_ADMITTED, True): (
        "the dollars are THIS entity's own priced holdings, and every asset observed at it was "
        "priced — so the figure is an AT-MOST on what replacing this node's code can move from "
        "it. The principal can replace that code, so none of the code that would have stood "
        "between them and these holdings is still standing; what is not witnessed is the other "
        "direction, that replaced code reaches every asset in the total, and an accounting entry "
        "rather than a held balance is inside the sheet and outside the move"
    ),
    (P.CEILING_ADMITTED, False): (
        "the dollars are THIS entity's own priced holdings and they DO NOT bound the move: the "
        "sheet does not cover everything observed here, so the total is a floor over what was "
        "priced and the entity holds more than it. What the figure bounds from above is the "
        "COVERED PORTION — replacing this node's code can move no more of those assets than the "
        "sum of them — and what the part it does not cover adds is not_determined here, which is "
        "why bound_direction is not a ceiling on this entry"
    ),
    (P.CEILING_PROVEN_EMPTY, True): (
        "the ceiling is a PROVEN ZERO and not a missing number: every asset observed at this "
        "entity carries a quantity witnessed zero, so replacing its code can move nothing from "
        "it. This is an earned negative — a sheet nobody priced publishes not_determined instead "
        "— and it bands at the floor for the same reason any small figure does"
    ),
    (P.CEILING_AIRDROP_DETERMINED, True): (
        "the ceiling is a DETERMINED ZERO of a different kind: every asset observed at this "
        "entity either carries a quantity witnessed zero or arrived ONLY in transactions "
        "carrying at least the published fan-out threshold of same-token transfer LOGS, so this "
        "sheet's determined content is nil and replacing the node's code moves nothing the "
        "document can price. The claim is DELIVERY SHAPE and never worth — real tokens have "
        "been measured arriving this way — and the asset list it covers is the one the index "
        "returned, refused only where that list was read AT the page cap"
    ),
    (P.CEILING_AIRDROP_DETERMINED, False): (
        "the ceiling is a determined zero of what this sheet PRICES: nothing observed at this "
        "entity carries a determined dollar reading above zero, and every reading that is not a "
        "witnessed zero arrived only in transactions carrying at least the published fan-out "
        "threshold of same-token transfer LOGS. It is NOT a figure over the disposed assets "
        "themselves — the claim admitting it is DELIVERY SHAPE, which says how they arrived and "
        "never what they are worth — and the coverage is not whole either, so what the part it "
        "does not cover adds is not_determined"
    ),
    # ``(PROVEN_EMPTY, False)`` is ABSENT, and its absence is a rule rather than
    # an omission. It described a proven-empty priced sheet at a node the
    # restaking plane also carries unpriced positions for; the sheet plane now
    # REFUSES the empty state there outright (``ValuePlane.proven_empty_refusal``
    # — a $0 beside those positions both contradicts a plane already in this
    # document and bounds a magnitude at zero over holdings nobody priced), so
    # such an entity publishes ``unpriced`` and earns no ceiling at all. A
    # sentence nothing can publish is removed on the same rule the uncalibrated
    # register is kept by, and the lookup below stays strict so a fifth
    # combination raises instead of borrowing one of these.
}

# True of every sheet ceiling whatever admitted it and whatever its coverage, so
# it is constant: it states what the entry does NOT claim, and asserts nothing
# about the row's own data.
_CEILING_CLOSING = (
    ". Whatever it bounds, it bounds from ABOVE and is never an amount — nothing here says the "
    "principal moves this — and it is scoped to THIS node: what the node in turn governs keeps "
    "its own rules, because that node's code is still standing. It charges no exposure for the "
    "same reason: an upper bound on an unwitnessed move is not expected loss, and spending an "
    "entity's exposure budget on one would displace a row that measured a real extraction there"
)

# Why the per-entity figure is or is not an at-most on the move, derived from
# that entity's OWN asset coverage. The row header asks the same question over
# the whole row (:func:`_bound_direction`) and refuses on the same conjunct; two
# surfaces answering it differently is the contradiction these strings exist to
# stop.
_SHEET_CEILING_DIRECTION_BASIS = {
    True: (
        "every asset observed at this entity carries a determined reading — a price, or a "
        "QUANTITY witnessed zero, which is worth nothing at any price — and no position carries "
        "an absent USD column, so the total covers the holdings and bounds the move from above"
    ),
    False: (
        "the priced sheet does not cover everything observed at this entity, so the total is a "
        "floor over what was priced and bounds the holdings in neither direction. What it does "
        "not cover, on this entity: "
    ),
}

# The conjuncts of ``_asset_coverage["complete"]``, each with the field the row
# publishes it under, so a refused direction names the cause that actually
# fired. Written as a table rather than as one sentence listing all three
# because two of them read EMPTY on live carriers — the $575M stETH proxy
# refuses on the third alone — and a sentence naming causes that did not fire
# is a sentence a reader cannot check against the row beside it.
#
# ONE table, and :func:`_coverage_shortfall` is its one reader, because the row
# publishes the same shortfall twice: once as the reason its direction is not a
# ceiling and once inside the reading that explains its figure. Two hand-written
# sentences over one fact is how they came to disagree — the direction basis was
# corrected and the reading's stem was left asserting the same false premise.
# Each entry is (published field, the value that FAILS the conjunct, the clause).
_SHEET_CEILING_INCOMPLETE_CAUSES: tuple[tuple[str, bool, str], ...] = (
    (
        "assets_not_priced",
        True,
        "assets observed here that no price lookup answered for (assets_not_priced)",
    ),
    (
        "unpriced_positions",
        True,
        "positions the restaking plane carries at this node with no USD column at all (unpriced_positions)",
    ),
    (
        "asset_list_proven_whole",
        False,
        "the asset LIST itself is not proven whole (asset_list_proven_whole, "
        "asset_set_completeness): the rows are what an index returned, and a disposition covers "
        "the readings observed and never the holdings, so nothing here establishes that these "
        "assets are all the entity has",
    ),
)


def _coverage_shortfall(coverage: dict[str, Any]) -> str:
    """Which conjuncts of ``complete`` this entity FAILED, off its own fields.

    The single derivation behind both surfaces that publish the shortfall. Every
    caller is on the ``complete is False`` arm, where at least one conjunct
    failed by construction, so the result is never empty.
    """
    return "; ".join(
        clause for field, fails_when, clause in _SHEET_CEILING_INCOMPLETE_CAUSES if bool(coverage[field]) is fails_when
    )


# The reading's own lead-in to the same derived clause the direction basis ends
# with. Only the framing differs — one sentence answers "why is this not a
# ceiling", the other "what does this figure leave out" — and the fact itself is
# derived once.
_CEILING_COVERAGE_SHORTFALL_PREFIX = ". What it does not cover, on this entity: "


def _sheet_ceiling_direction_basis(coverage: dict[str, Any], complete: bool) -> str:
    """Why this entity's own figure is or is not an at-most on the move.

    The refusing arm ENUMERATES the conjuncts that failed, off the row's own
    published fields, because the sentence has to explain its own carrier: two
    entities on the reference corpus refuse with ``assets_not_priced`` empty and
    ``unpriced_positions`` zero, and a constant naming only those two told a
    reader to look at fields that say nothing.
    """
    if complete:
        return _SHEET_CEILING_DIRECTION_BASIS[True]
    return _SHEET_CEILING_DIRECTION_BASIS[False] + _coverage_shortfall(coverage)


# One name per component of :func:`_composed_order`'s key, positionally. The
# published ``chosen_by`` reads the component that ACTUALLY separated this
# candidate from each one it was chosen over, so the names have to line up with
# the tuple; a length mismatch is a fixture-free way for the string to name the
# wrong rule, and it is asserted rather than trusted.
_ORDER_COMPONENT_NAMES = (
    "the published figure, highest",
    "the weakest witness state",
    "the lowest selector",
    "the lowest destination function",
    "the chain's calling selectors, in order",
    "the chain's own published identity",
)


@dataclass(frozen=True)
class _ComposedMagnitude:
    """A destination function's own magnitude witness, reached along a witnessed path.

    ``chain`` is every act-as step from the seized node to the destination, in
    order. ``usd`` is the destination witness's figure after the R4 bound against
    the destination's own sheet; the published ``bounded_by`` says which of the
    two bound it, and ``sheet_not_determined`` marks the case where no sheet was
    available to bound it with at all. Both of those bounds are ceilings and so
    is their min.

    ``tied_with`` is the other candidates this entity offered at the SAME figure,
    which this one was chosen over by :func:`_composed_order`. Empty is the
    proven "one candidate, nothing was decided by the rule", and it publishes as
    ``composed_selector_tie: null`` rather than as a missing field.

    ``predicates`` is the destination function's own stored condition texts, a
    disclosure carried so the entry can point at them; nothing in this class or
    anywhere downstream evaluates one. It is REQUIRED, with no default: the
    lookup answers in three states of its own and a default would have to spell
    one of them, putting "nobody asked" and "asked, and no function of this
    entity carries that selector" under one name — inside the very block whose
    reading argues those must stay apart.
    """

    entity: str
    selector: str
    function: str
    witness_state: str
    witnessed_usd: float
    usd: float
    sheet_usd: float | None
    chain: tuple[P.ActAsStep, ...]
    predicates: P.DestinationPredicates
    # The call that PROVED ``witnessed_usd`` at the destination. REQUIRED, with
    # no default: the invariant is that a published magnitude carries its
    # execution, and a default would let an entry ship the figure while silently
    # claiming nothing about the call — which is the state every entry is in
    # today and precisely what this field exists to make visible.
    execution: EX.ProvingExecution
    # Why the destination's sheet did not bound this figure, where a sheet
    # EXISTS and is determined and still may not trim. ``None`` on every other
    # entry, including the ones with no sheet at all: "there is no number here"
    # and "there is a number and it does not answer this question" are different
    # facts, and ``sheet_not_determined`` may only ever spell the first.
    sheet_bound_refused: str | None = None
    # What the destination sheet's OWN asset coverage proves about the cap it
    # applied — read at the trim site from the same :func:`_asset_coverage` the
    # sheet-ceiling records publish their ``bound_direction`` from, so the two
    # surfaces answer "is this sheet an at-most" the same way. ``None`` is the
    # third state and the only one available to an entry built without a plane:
    # nobody read the coverage. It publishes ``not_determined``, never
    # ``ceiling`` — the absence of a completeness proof is not a completeness
    # proof, and a trim onto an unproven ceiling is how a witnessed magnitude
    # gets quietly reduced to a floor over what somebody happened to price.
    sheet_is_proven_complete: bool | None = None
    sheet_bound_direction_basis: str | None = None
    tied_with: tuple[_ComposedMagnitude, ...] = ()
    # Which arm of the composition rule this entry took, and the two witnesses
    # the arm was taken from. All three are set by :func:`_admit_composed` after
    # selection and default to "nothing was decided": a candidate that never
    # reached the rule publishes ``not_determined`` and no basis, which is what
    # it is. A PUBLISHED entry always carries ``republished_direct``, because the
    # other three arms withhold the figure and leave the composed dict.
    arm_taken: str = ARM_NOT_DETERMINED
    deletability: P.DeletabilityVerdict | None = None
    route: P.RouteClassification | None = None

    def __post_init__(self) -> None:
        # The two coverage fields are one answer read at one place, so they are
        # present together or absent together. Split, an entry could publish a
        # direction with no basis — the shape this fix exists to remove.
        if (self.sheet_is_proven_complete is None) != (self.sheet_bound_direction_basis is None):
            raise ValueError("sheet coverage and its basis are read together and publish together")

    @property
    def sheet_bound_direction(self) -> str | None:
        """Whether the destination sheet PROVES an at-most on this entry's figure.

        ``None`` where no sheet bounded anything — the entry says that under
        ``sheet_not_determined`` and ``sheet_bound_refused`` and does not need a
        direction for it. Otherwise the same two-valued answer the per-entity
        sheet-ceiling records publish, off the same conjunction: a priced sheet
        that does not cover everything observed at the node is a floor over what
        was priced, and ``min(witness, sheet)`` against such a figure hands back
        a NUMBER SMALLER than the witness on the strength of a bound nothing
        proved. The figure stands — it is the honest min of what is known — and
        the entry stops calling it a ceiling.
        """
        if self.sheet_usd is None:
            return None
        return BOUND_DIRECTION_CEILING if self.sheet_is_proven_complete else BOUND_DIRECTION_NOT_DETERMINED

    def _chain_identity_gloss(self) -> str:
        """What the order's last component actually ranges over, read off the steps.

        The shipped gloss named five fields — caller, selector, calling selector,
        receiver variable, receiver block — and :func:`_composed_order`'s tail is
        every field ``P.ActAsStep.as_json`` publishes, which is more than five and
        grows. Under-stating the key it describes made the string false of every
        carrier (``COMPOSITION_WITNESS_SHAPE_SPEC.md`` §11.2 (k)). Reading the
        field names off the steps in hand keeps the gloss exhaustive by
        construction, including on the day a step publishes a new field.
        """
        fields = sorted({name for entry in (self, *self.tied_with) for step in entry.chain for name in step.as_json()})
        if not fields:
            return (
                "Its last component is every field each act_as_chain step publishes, and no "
                "candidate here publishes a step at all, so that component is empty on all of "
                "them and separates nothing"
            )
        return (
            "Its last component is EVERY field each act_as_chain step publishes — on these "
            "candidates " + ", ".join(fields) + " — taken from the step's own published shape "
            "rather than from a list written into this sentence, so the key stays total over "
            "the entry on the day a step publishes a new field"
        )

    def _chosen_by(self) -> str:
        """The rule, and the component of it that decided THIS tie.

        Reciting the whole ladder reads as though every component applied. It did
        not: on a tie the components ahead of the deciding one hold the same
        value on every candidate — the figure always does, by the definition of
        a tie — and the ones behind it are never reached. So the deciding
        component is computed per tie, against each candidate this entry was
        chosen over, and the case where the order separates nothing is published
        as itself rather than left to read as a decision.
        """
        key = _composed_order(self)
        decided: dict[int, int] = defaultdict(int)
        unseparated = 0
        for other in self.tied_with:
            component = _first_differing_component(key, _composed_order(other))
            if component is None:
                unseparated += 1
            else:
                decided[component] += 1
        named = [
            f"{_ORDER_COMPONENT_NAMES[index]} (component {index + 1} of {len(key)}) against {hits} candidate(s)"
            for index, hits in sorted(decided.items())
        ]
        if not named:
            what_decided = (
                f"This order decides NOTHING here: every component of the key holds the same "
                f"value on all {unseparated} of them, so which one is published rests on the "
                f"order the candidates were built in and not on this rule"
            )
        else:
            what_decided = (
                "What decided it: "
                + "; ".join(named)
                + " — in each case the FIRST component on which this entry differs from that "
                "candidate. The components ahead of a deciding one hold the same value on every "
                "candidate in this tie and decided nothing, and the components behind it were "
                "never reached"
            )
            if unseparated:
                what_decided += (
                    f". It separates this entry from {unseparated} of them not at all — every "
                    "component of the key is equal there, so which of those is published rests "
                    "on the order the candidates were built in and not on this rule"
                )
        return (
            f"the total order at _composed_order, over the {len(self.tied_with) + 1} candidates "
            "this entity offered at the same published figure: "
            + "; then ".join(_ORDER_COMPONENT_NAMES)
            + ". "
            + self._chain_identity_gloss()
            + ". "
            + what_decided
        )

    def _tie_json(self) -> dict[str, Any] | None:
        if not self.tied_with:
            return None
        return {
            "tied_at_usd": _round_published(self.usd),
            "candidates": [
                {
                    "selector": entry.selector,
                    "destination_function": entry.function,
                    "witness_state": entry.witness_state,
                    "witnessed_usd": _round_published(entry.witnessed_usd),
                    "chosen": entry is self,
                }
                for entry in sorted((self, *self.tied_with), key=_composed_order)
            ],
            "chosen_by": self._chosen_by(),
            "reading": (
                "this entity carries more than one call at the same PUBLISHED figure, and "
                "which of them names the published selector, destination_function and "
                "act_as_chain is decided by that rule and not by evidence. The published "
                "dollars are the same under every one of them, so nothing about the figure "
                "rests on the choice — but the candidates are not therefore equally "
                "witnessed: witnessed_usd is each one's OWN flow.out figure and they can "
                "differ where the destination's sheet is what capped them to the same number. "
                "The witness state published is the WEAKEST of the tied candidates, so no "
                "exactness is claimed that a tied candidate does not support"
            ),
        }

    @property
    def bounded_by(self) -> str:
        """Which of the two ceilings was the binding one on THIS entry.

        A property rather than an inline expression in :meth:`as_json` because
        the published ``reading`` is derived from it: the sentence naming where
        the dollars came from has to say the same thing this field does, and
        computing the answer twice is how the two drift apart.
        """
        return (
            _BOUNDED_BY_WITNESS if self.sheet_usd is None or self.witnessed_usd <= self.sheet_usd else _BOUNDED_BY_SHEET
        )

    def _predicates_json(self) -> dict[str, Any]:
        found = self.predicates
        reading = (
            "the predicate texts extracted from the DESTINATION function's compiled body, "
            "published verbatim and in stored order so this entry's ceiling can be checked "
            "against the evidence rather than taken on the fold's word. Three things about "
            "them. (1) They are stored WITHOUT POLARITY: the same text is a require-condition "
            "in one function and a revert-condition in another, so nothing here can tell "
            "whether any one of them must hold or must not. (2) The scorer therefore EVALUATES "
            "NONE of them and no published figure, band, refusal or count is affected by any "
            "one of them — removing this block changes no number. (3) The list is not a list of "
            "unmet business conditions: it may include the authorization guard that this step's "
            "own act-as witness proves satisfied, and it may include transfer post-conditions "
            "and compiler or decompiler artefacts, all of which the extractor labels 'business' "
            "alike — which is why the label is not read and the list is not filtered. state is "
            "three-valued and the three are not "
            "interchangeable: 'extracted' is a read (count 0 under it means the extractor ran "
            "and found no predicate), 'column_holds_no_array' is an extraction that never ran, "
            "and 'destination_function_not_located' is a join that found no function of this "
            "entity under this selector — under the last two, descriptions is null and not an "
            "empty list, because nothing was read. function_name is the row the selector join "
            "landed on, published so a reader can check it against destination_function above "
            "rather than take the join on the fold's word"
        )
        return {
            "source": "effective_functions.conditions",
            "state": found.state,
            "function_id": found.function_id,
            # The name of the row the join reached, NOT this entry's
            # ``destination_function`` restated: the first comes from
            # ``effective_functions``, the second from the flow.out signal, and
            # printing one twice would hide the day they disagree.
            "function_name": found.function_name,
            "functions_matching_selector": found.functions_matching,
            "count": (None if found.descriptions is None else len(found.descriptions)),
            "entries_stored": found.entries_stored,
            "descriptions": (None if found.descriptions is None else list(found.descriptions)),
            "evaluated": False,
            "reading": reading,
        }

    def as_json(self) -> dict[str, Any]:
        return {
            "entity": self.entity,
            "destination_function": self.function,
            "selector": self.selector,
            # The invariant, published: a magnitude names the execution that
            # produced it, and every claim attached to it is derived from that
            # record. Where the record is not_determined the block says so with
            # a typed reason and publishes no caller — an unread execution is
            # never a matching one.
            "proving_execution": self.execution.as_json(),
            "route_comparison": EX.route_comparison(
                self.execution,
                claimed_caller=self.chain[-1].caller if self.chain else None,
                claimed_target=self.chain[-1].destination if self.chain else None,
                claimed_selector=self.chain[-1].calling_selector if self.chain else None,
            ),
            # Which arm of the composition rule produced this entry, and what
            # licensed it. Published beside the comparison it is decided from
            # rather than left to be inferred from whether a figure is present.
            "arm_taken": self.arm_taken,
            # §7.2 arm 1's caller conjunct, evaluated rather than left implicit.
            "gate_claim": _gate_claim(self.chain, self.execution),
            # The route the proof took is republished as this entry's own only
            # where the deletability join proved this principal can author the
            # destination's calldata itself. The basis names the row that proved
            # it — the setter selector and the ``function_principals`` id — so
            # the licence can be checked rather than taken on the fold's word.
            "authority_deletability": (None if self.deletability is None else self.deletability.disclosure()),
            "route_classification": (None if self.route is None else self.route.as_json()),
            "flow_out_witness": {
                "state": self.witness_state,
                "usd": _round_published(self.witnessed_usd),
                "function": self.function,
                "entity": self.entity,
            },
            # The figure was READ from the row destination_function/selector
            # name, and what it measures is the ENTITY's: every selector at a
            # vault on the reference corpus carries the identical number. Named
            # so the pair is not read as a per-function decomposition.
            "witness_granularity": "entity",
            # EVERY dollar figure on this record takes the same rounding, and the
            # reason is not tidiness: the record publishes ORDERING and EQUALITY
            # claims across these fields. ``published_usd`` is the min of
            # ``flow_out_witness.usd`` and ``destination_sheet_usd``, ``bounded_by``
            # names which of the two it equals, and ``composed_selector_tie`` says
            # the candidates tie AT the published figure. Round one of them onto
            # zero and not its neighbours and the record breaks its own
            # invariants — a $0.00 witness above a $0.00156 published bound — so
            # the sub-cent case is exactly where a mixed convention publishes a
            # contradiction instead of a rounding.
            "destination_sheet_usd": (_round_published(self.sheet_usd) if self.sheet_usd is not None else None),
            "published_usd": _round_published(self.usd),
            # Which of the two ceilings was the binding one. Not
            # flow_out_witness.state, which says whether the destination's own
            # dollar figure for one call is exact or a priced floor.
            "bounded_by": self.bounded_by,
            # STRICTLY "no number was available". A sheet that carries a number
            # and is barred from trimming publishes its bar under its own key
            # below, so this one never has to stand for two facts.
            "sheet_not_determined": self.sheet_usd is None and self.sheet_bound_refused is None,
            "sheet_bound_refused": self.sheet_bound_refused,
            # Whether the sheet that capped this figure is proven to be an
            # at-most, and — where it is not — WHICH conjunct of that proof is
            # missing, enumerated off the destination's own coverage by the same
            # derivation the per-entity ceiling records use. ``null`` on an entry
            # no sheet bounded: there is no direction to publish and
            # ``sheet_not_determined`` beside it already says so.
            "destination_sheet_bound_direction": self.sheet_bound_direction,
            "destination_sheet_bound_direction_basis": (
                None if self.sheet_usd is None else self.sheet_bound_direction_basis
            ),
            "act_as_chain": [step.as_json() for step in self.chain],
            "act_as_chain_length": len(self.chain),
            "destination_predicates": self._predicates_json(),
            # ``null`` is the proven "one candidate — the order decided nothing
            # here", which is a different fact from a field nobody filled in.
            "composed_selector_tie": self._tie_json(),
            "reading": (
                _COMPOSED_SOURCE_READINGS[self.bounded_by]
                + (f". {_DISPOSED_SHEET_DOES_NOT_BOUND}" if self.sheet_bound_refused else "")
                # Gated on the BASIS being present, not on the direction alone.
                # The sentence's job is to point a reader at two fields, and the
                # basis is null in the third state — a sheet exists and nobody
                # read its coverage — so emitting it there would send a reader
                # to a field that says nothing, which is the defect one level up
                # from the one it was written to fix. The typed direction still
                # publishes not_determined in that state and carries the refusal
                # on its own.
                + (
                    f". {_TRIMMED_TO_AN_UNPROVEN_CEILING}"
                    if self.bounded_by == _BOUNDED_BY_SHEET
                    and self.sheet_bound_direction != BOUND_DIRECTION_CEILING
                    and self.sheet_bound_direction_basis is not None
                    else ""
                )
                + ". "
                "Every hop from the seized node to it carries "
                "its own act-as witness, in one of two admissible shapes named per step under "
                "witness_kind: "
                "the CALLER'S OWN state variable, read on-chain holding the next node, or — "
                "where the call site takes its callee as a parameter, so no storage of the "
                "caller CAN name it — the next node's OWN access-control list naming this "
                "caller as an accepted caller of that selector by an enumerated role. Beyond "
                "the first hop the calling function must also be one the previous hop "
                "admitted, matched on that function's own selector — compare each step's "
                "calling_selector against the selector of the step before it — because no hop "
                "inherits its predecessor's authority and a function name does not identify a "
                "function. Remove any one of those witnesses and this figure is not_determined. "
                "Two further blocks say what this entry does NOT rest on. "
                "composed_selector_tie, where more than one call at this entity carried the "
                "same published figure and a stated rule rather than evidence picked which of "
                "them names the fields above — null there is the proven 'one candidate, and "
                "the rule decided nothing', never an unasked question. And "
                "destination_predicates, the destination function's own stored condition "
                "texts, published verbatim and evaluated by nothing here"
            ),
        }


def _composed_order(entry: _ComposedMagnitude) -> tuple[Any, ...]:
    """The total, evidence-first order a composed candidate is chosen by.

    Dollars first and highest: two selectors at one entity are two INDEPENDENT
    calls, the row asks what the principal can move, and a max of ceilings is a
    ceiling. (That is not the lower-of-two rule at
    :func:`_destination_magnitudes`, which settles two distillations of ONE
    quantity.) Everything after the figure breaks a tie between candidates that
    carry the same dollars, where the remaining published fields — the witness
    state, the selector, the destination function and the chain — are not
    dollars and are not interchangeable. The witness state goes to the weakest;
    the rest is arbitrary, and being arbitrary is exactly why it is stated here
    and published on the entry rather than left to the order instances arrive
    in.

    The tail is TOTAL over everything the entry publishes, and that is the point
    rather than a nicety. Two candidates can agree on the figure, the state, the
    selector, the function and the chain's shape and still differ in the raw
    destination the walk anchored on, the calling function's name, the witness
    kind, the observation the pointer was read under or the destination's
    acceptance row — all of which are rendered into ``act_as_chain`` and every
    step ``basis``. A key that stopped short would hand that difference back to
    the order the candidates were built in, which is the defect this ordering
    exists to remove, one level down.

    So the tail is the step's OWN published identity, taken from
    :meth:`P.ActAsStep.as_json` rather than from a hand-written list of fields.
    That is what makes it total by construction, and what keeps it total on the
    day a field is added to the step: a list written out here would silently
    stop covering the entry the moment the step published something new. Values
    are rendered to text because the published shape is not orderable as it
    stands — ``destination_acceptance`` is a nested object on one step and
    ``None`` on the next, and comparing those two directly raises.
    """
    return (
        -entry.usd,
        _WITNESS_STATE_CLAIM.get(entry.witness_state, _WITNESS_STATE_UNRANKED),
        entry.selector,
        entry.function,
        # Length needs no component of its own: two chains whose calling
        # selectors compare equal are the same length by construction.
        tuple(step.calling_selector or "" for step in entry.chain),
        tuple(tuple(sorted((key, repr(value)) for key, value in step.as_json().items())) for step in entry.chain),
    )


def _first_differing_component(chosen: tuple[Any, ...], other: tuple[Any, ...]) -> int | None:
    """The index of the component that decided ``chosen`` over ``other``.

    ``None`` where no component differs — the two candidates are equal under the
    whole key and the order decided nothing between them. That is a real third
    state on a total-by-construction key (two candidates can agree on every
    ordered field and still differ in fields the key does not read, such as the
    execution that proved each one), and the published ``chosen_by`` says so
    rather than naming a component that separated nothing.
    """
    for index, (mine, theirs) in enumerate(zip(chosen, other)):
        if mine != theirs:
            return index
    return None


def _select_composed(candidates: list[_ComposedMagnitude]) -> _ComposedMagnitude:
    """The one candidate published for an entity, carrying the ones it beat.

    The WHOLE candidate is selected, never a field of it: ``selector``,
    ``function``, ``witness_state``, ``execution`` and ``chain`` are one
    call's account of itself, and a chain taken from a different candidate than
    the selector would publish a path that does not end at the function named
    beside it.

    Candidates tied at the published figure are retained on the winner so the
    entry can say that its selector, destination function and chain were decided
    by a stated rule rather than by evidence. Candidates BELOW the figure are
    dropped: they lost on dollars, which is a decision the evidence made, and
    keeping them would spell a resolved comparison as a tie.
    """
    ordered = sorted(candidates, key=_composed_order)
    best = ordered[0]
    tied = tuple(other for other in ordered[1:] if other.usd == best.usd)
    return replace(best, tied_with=tuple(replace(other, tied_with=()) for other in tied))


def _pool_composed(into: dict[str, list[_ComposedMagnitude]], published: dict[str, _ComposedMagnitude]) -> None:
    """Fold one composition's published entries back into a candidate pool.

    A published entry carries the candidates it was chosen over, so re-selecting
    over ``entry`` plus ``entry.tied_with`` reaches the same answer as selecting
    over the whole population at once — which is what lets the two selection
    points (one per :func:`_compose`, one across a row's instances) compose
    without the second inheriting the first's tie-break as if it were evidence.

    Duplicates are dropped on the entry's own fields: the same call reached by
    two instances of one row is one candidate, and counting it twice would
    publish a tie where nothing was ever ambiguous.
    """
    for key, entry in published.items():
        pool = into.setdefault(key, [])
        for candidate in (replace(entry, tied_with=()), *entry.tied_with):
            if candidate not in pool:
                pool.append(candidate)


# Which direction the row's own ``value_at_stake_usd`` bounds the principal in.
# A DIFFERENT axis from ``VALUE_BOUND_*`` on a signal (whether the entity SET is
# the whole reach or a floor over it) and from ``flow_out_witness.state`` (which
# grades the pricing of one call), and the three are not interchangeable.
#
# Three states, and only two of them are claims. ``not_determined`` is the third
# and it is the fall-through, because a direction is a positive fact about a SUM
# and this fold does not grade every contribution for direction: a total with no
# coverage gap and no composed ceiling in it is still summed out of figures that
# may each be a priced floor, so "neither signal fired" is not a proof that the
# figure is two-sided. It publishes the bare band, exactly as before this field
# existed, and says in the basis what it did not establish — but only where a
# ceiling is what defeated the claim: the no-ceiling fall-through leaves the
# row's own basis untouched, because that basis was never a bound claim to
# correct and rewriting it would move prose on rows nothing moved on.
BOUND_DIRECTION_FLOOR = "floor"
BOUND_DIRECTION_CEILING = "ceiling"
BOUND_DIRECTION_NOT_DETERMINED = NOT_DETERMINED
# The band label's qualifier, written only for the two proven directions. A
# qualifier that cannot be earned is not written at all.
_BAND_PREFIX = {BOUND_DIRECTION_FLOOR: ">= ", BOUND_DIRECTION_CEILING: "<= "}

# The two directions a per-entity SHEET figure can earn, the same pair
# ``_SHEET_CEILING_DIRECTION_BASIS`` is keyed on: an entity whose priced sheet
# covers everything observed at it bounds the move from above, and one holding
# assets nobody priced bounds it in neither direction. ``floor`` is absent
# deliberately — a sheet figure is never one — so the rollup's census reports
# the two that can be earned and does not invent a bucket for the one that
# cannot.
SHEET_CEILING_BOUND_DIRECTIONS = (BOUND_DIRECTION_CEILING, BOUND_DIRECTION_NOT_DETERMINED)


@dataclass
class _RowValue:
    """What one row's instances proved about value, and what they did not."""

    per_entity: dict[str, float]
    total_usd: float | None
    basis: str
    undetermined: list[dict[str, Any]]
    proven_no_reach: list[dict[str, Any]]
    # Witnessed membership, NOT the keys of ``per_entity``: an entity whose
    # dollars are not_determined is still an entity the row provably reaches.
    reach: set[str]
    magnitude_caps: list[dict[str, Any]]
    # Hops the walk could not establish either way, deduped on the distinct
    # (caller, destination) pair, and the census of which instances carried a
    # magnitude witness at all.
    hops_not_determined: list[dict[str, Any]] = field(default_factory=list)
    magnitude_census: dict[str, int] = field(default_factory=dict)
    # What the walked gate hops LICENSE at each destination: the named functions
    # the role -> selector join resolved. Empty for a destination reached only
    # through state-variable hops, where nothing named which functions the gate
    # reaches — an absence, never an empty licence.
    licensed_functions: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    # How much of the graph the withheld hops hide. A frontier hop published as
    # not_determined names ONE destination; everything the closure places behind
    # it is withheld too and appears nowhere on the row.
    withheld_behind_hops: dict[str, Any] = field(default_factory=dict)
    # Floor magnitudes charged against an entity whose priced sheet is
    # not_determined, so nothing was available to bound them with. Published
    # rather than absorbed: the figure is the witness's, not the entity's.
    unbounded_floor_magnitudes: list[dict[str, Any]] = field(default_factory=list)
    # Phase 6: the destination witnesses that supplied a gate-control magnitude,
    # the census of how far every licensed hop got, and the signals whose
    # magnitude question composition answered.
    composed_magnitudes: dict[str, _ComposedMagnitude] = field(default_factory=dict)
    composition_census: dict[str, Any] = field(default_factory=dict)
    composed_signals: frozenset[tuple[Any, ...]] = frozenset()
    # Entities whose PUBLISHED figure in ``per_entity`` bounds this principal
    # from ABOVE and not from below, from EITHER ceiling — the composed
    # destination witness or the controlled node's own sheet. Threaded rather
    # than re-derived from ``composed_magnitudes``: that map holds every entity a
    # composed candidate was built for, including ones whose own witness beat it
    # in the per-entity MAX, and the header's question is which figures WON.
    ceiling_entities: frozenset[str] = frozenset()
    # The SHEET half of the set above, published apart and never inferred as the
    # complement: the two ceilings are not each other's negation (a row can carry
    # both, and an entity is in exactly one), and only this half is kept out of
    # the exposure numerator. An entity here is one whose standing figure is its
    # own priced sheet, admitted because this row's capability replaces that
    # node's code.
    sheet_ceiling_entities: frozenset[str] = frozenset()
    # The signals whose sheet ceiling STANDS as this row's published figure at
    # some entity, on ``composed_signals``' pattern. Rolled up to the protocol so
    # the confidence pass can credit a proven bound as an answered magnitude
    # question without re-deriving which signals produced one. A signal whose
    # ceiling was displaced by a larger figure is absent: a credited answer has
    # to have a carrier in the document.
    ceiling_signals: frozenset[tuple[Any, ...]] = frozenset()
    # Entities the S6 reconciliation refused the ceiling LABEL to, with both
    # figures. Carried rather than dropped for the reason every refusal on this
    # row is: an entity silently absent from the ceiling list is
    # indistinguishable from one the branch never fired on.
    sheet_ceilings_withheld: list[dict[str, Any]] = field(default_factory=list)
    # F5: the entities whose STANDING figure is PROVEN not to be
    # attribution-derived. An earned positive and NOT the complement of
    # ``ceiling_entities`` — that one says which BRANCH supplied a figure, this
    # one says what the WITNESS behind it claims, and the two are orthogonal (an
    # attribution-derived figure bounds from above whether it arrived through
    # composition or through the instance's own witness). An entity missing from
    # this set is one whose provenance was not established, which is exactly as
    # disqualifying for a floor as a proven attribution.
    non_attributed_entities: frozenset[str] = frozenset()
    # The composed candidates whose FIGURE the three-arm rule refused, and the
    # refusal counter keyed on the deletability verdict's ``(state, reason)``.
    # Carried on the row rather than summed away, because a row that loses EVERY
    # composed figure publishes an empty ceiling list, and an empty list on such
    # a row is otherwise indistinguishable from an empty list on the seventy-odd
    # rows that never composed anything — which launders a typed refusal into
    # silence.
    withheld_composed_magnitudes: tuple[_WithheldComposition, ...] = ()
    refused_composed_magnitudes: dict[str, int] = field(default_factory=dict)


def compute_protocol_score(
    session: Session,
    protocol_id: int,
    *,
    signals: list[FunctionSignal] | None = None,
    trigger: str = SCORE_TRIGGER_MANUAL,
    trigger_job_id: Any | None = None,
    computed_at: datetime | None = None,
    universe: ProtocolUniverse | None = None,
) -> ScoreDocument:
    """The protocol's score document, folded over its current signal rows.

    ``signals`` is the §7.5 in-memory feeding mode and nothing else: the offline
    CLI distils every contract without persisting, and passes the result in the
    population order :func:`order_signals` pins. Left unset — every persisted
    path — the population comes from the one pinned query and from nowhere else,
    so no caller can hand the fold a filtered or re-ordered population.

    ``universe`` is the protocol's discovered address set, built in ``distill``
    because assembling it reads object storage and this fold may not. UNSET is
    the fail-closed default and it means no reading is disposed anywhere: the
    predicate it feeds condemns what is ABSENT from the set, so an absent set
    would condemn everything. Every hand-built plane in the suite relies on that
    default, and so does every caller that has no storage to read.
    """
    row_faults: list[dict[str, Any]] = []
    if signals is None:
        # A row whose persisted JSONB does not hold its declared shape withholds
        # ITSELF: the schema's canonical-key checks are the right checks, but
        # raising them through the population read costs the whole protocol its
        # score over one bad column.
        signals, row_faults = current_signals_with_faults(session, protocol_id)

    value_plane = P.load_value_plane(session, protocol_id, universe=universe)
    closure = P.load_control_closure(session, protocol_id)
    conditions = P.load_condition_plane(session, protocol_id)
    conferral = P.load_conferral_plane(session, protocol_id)
    act_as = P.load_act_as_plane(session, protocol_id)
    # ``load_deletability_plane`` takes NO protocol_id, unlike every loader
    # around it: it asks about specific (chain, address) contracts, which are
    # global on-chain identities, and scoping it would drop setter rows on
    # contracts this protocol does not own — turning our own scoping into an
    # earned negative about somebody's control.
    admission = _AdmissionPlanes(P.load_deletability_plane(session), P.load_router_flow_plane(session, protocol_id))
    role_floors = P.load_role_holder_floors(session, protocol_id)
    refs = [ref for signal in signals for ref in signal.principal_refs]
    refs.extend(_recovery_refs(signals))
    principal_facts = P.load_principal_plane(session, refs)

    warnings: list[dict[str, Any]] = [
        {
            "kind": "signal_row_malformed",
            "entity": fault["entity"],
            "function": fault["function_name"],
            "capability": fault["claim_id"],
            "note": f"signal row withheld: {fault['column']} does not hold its declared shape",
            "column": fault["column"],
            "detail": fault["detail"],
        }
        for fault in row_faults
    ]
    earned_negatives: list[dict[str, Any]] = []
    seen_negatives: set[tuple[str, str]] = set()

    units = _UnitResolver(signals, principal_facts, role_floors)
    rows_by_key: dict[tuple[str, str, str], _Row] = {}

    for signal in signals:
        malformed = _malformed_gates(signal)
        if malformed:
            # One unreadable envelope withholds its own row. Raising here would
            # take the whole protocol's grade down with one bad payload, and
            # scoring around it would read a payload nobody validated.
            warnings.append(_warning("gate_input_malformed", signal, f"unreadable gate envelopes: {malformed}"))
            continue

        _collect_disclosures(signal, earned_negatives, seen_negatives, warnings)
        if not signal.enters_grade:
            continue

        if signal.authority_openness == OPENNESS_OPEN:
            severity, severity_basis, extra_notes = _fold_severity(signal, None, principal_facts, warnings)
            instance = _instance(signal, severity, severity_basis, ANYONE)
            unit = entity_key(signal.chain, ANYONE)
            row = _row_for(rows_by_key, unit, signal.claim_id, "direct", K.WEAKNESS_ANYONE, "ANYONE", ANYONE, ANYONE)
            _attach(row, signal, instance, extra_notes)
            continue

        if signal.authority_openness == OPENNESS_NOT_DETERMINED:
            warnings.append(_warning("unresolved_reachability", signal, "authority_openness is not_determined"))
            continue

        if signal.principal_state != PRINCIPAL_STATE_ENUMERATED:
            warnings.append(
                _warning("restricted_privileged_no_principal", signal, "no resolved principal and no earned empty")
            )
            continue

        for ref in signal.principal_refs:
            facts = principal_facts.get(int(ref.function_principal_id))
            if facts is None:
                warnings.append(_warning("principal_row_missing", signal, f"principal {ref.address} not readable"))
                continue
            severity, severity_basis, extra_notes = _fold_severity(signal, facts, principal_facts, warnings)
            instance = _instance(signal, severity, severity_basis, facts.address)
            weakness, label, kind, notes = units.weakness_for(
                facts,
                recovery_proven_independent=any(n.startswith("keyset_independent") for n in extra_notes),
            )
            if weakness is None:
                warnings.append(
                    _warning(
                        "contract_gated_unknown_path" if kind == "contract" else "unresolved_principal",
                        signal,
                        f"gated by a {label} principal whose own authority is not reduced to a key",
                        principal=facts.address,
                    )
                )
                continue
            unit = units.unit_for(facts)
            row = _row_for(
                rows_by_key,
                unit,
                signal.claim_id,
                units.path_for(facts),
                weakness,
                label,
                kind,
                facts.address,
            )
            _attach(row, signal, instance, extra_notes | set(notes))

    composed_signals: set[tuple[Any, ...]] = set()
    ceiling_signals: set[tuple[Any, ...]] = set()
    composition_census: dict[str, Any] = {}
    findings, subsumed, value_warnings = _aggregate(
        rows_by_key,
        value_plane,
        closure,
        conditions,
        conferral,
        act_as,
        _destination_magnitudes(signals),
        admission,
        units,
        composed_signals,
        ceiling_signals,
    )
    warnings.extend(value_warnings)
    composition_census = _composition_totals(findings, subsumed)

    # A transport fault takes the composition rule's withheld arm and moves the
    # grade, so it must not be discoverable only by reading every execution
    # block: an artifact store that stops answering would otherwise look exactly
    # like a code regression.
    execution_faults = _execution_fault_census(findings, subsumed)
    if execution_faults is not None:
        warnings.append(_execution_fault_warning(execution_faults))

    grade_lambda, grade_exposure, exposure_usd, exposure_gaps, exposure_coverage = _grade(findings, value_plane)
    confidence = _confidence(
        signals,
        value_plane,
        closure,
        P.load_proven_eoa_entities(session, protocol_id),
        P.discovery_relation_entities(session, protocol_id),
        composed_signals,
        ceiling_signals,
    )

    perimeter, perimeter_detail = P.perimeter_state(session, protocol_id)
    provenance: dict[str, Any] = {
        "plane_row_counts": P.plane_row_counts(session, protocol_id),
        "population": {
            "signals": len(signals),
            "signals_entering_grade": sum(1 for s in signals if s.enters_grade),
            "findings": len(findings),
            "subsumed_rows": len(subsumed),
            # The distinction the read surface cannot make on its own: an
            # un-analysed protocol and a fully-undetermined one both reach a
            # consumer as grade_state=not_determined.
            "disposition": _population_disposition(signals, findings),
            "rows_withheld_malformed": len(row_faults),
        },
        "value": value_plane.provenance,
        "value_annotations": value_plane.annotations,
        # Each closure admission rule, counted where it fired AND where it did
        # not. A refusal and an earned negative are different facts about the
        # same row: the first says what this scorer declined to walk, the second
        # says the protocol has proven an authority slot empty, and only the
        # second is evidence about the protocol.
        "closure_admission": {
            "refusals": closure.refusal_counts(),
            "renounced": closure.renounced_counts(),
            "reading": (
                "refusals are EDGES this closure declined to admit, by rule: the zero address "
                "is a burn sentinel and not an assessable entity, so it is refused as principal "
                "and as anchor rather than becoming the largest control hub in the graph. "
                "renounced counts controller_value edges pointing AT the zero address, which is "
                "an authority slot proven EMPTY — renunciation for an ownership slot, an unset "
                "reference for a configuration pointer, proven-absent authority either way. "
                "edges is the citable row population; authority_slots is the distinct "
                "(anchor, label) it resolves to, which is the number of facts — the edge table "
                "carries one row per witnessed read, so the two differ by how often the "
                "resolver looked and never by how much authority was renounced"
            ),
        },
        # What bounds a reach hop, and where the bound could not be established.
        # A closure that walks every edge publishes reach it never proved; one
        # that silently drops the edges it cannot establish publishes a smaller
        # number with the same defect. Both classes' populations are counted.
        "reach_bounds": {
            "code_control_capabilities": sorted(K.CODE_CONTROL_CAPABILITIES),
            "gate_control_capabilities": sorted(K.GATE_CONTROL_CAPABILITIES),
            "caller_conditions": conditions.provenance,
            "gate_conferral": conferral.provenance,
            "act_as_composition": {**act_as.provenance, "census": composition_census},
            "hop_census": _hop_census(closure, conditions, conferral),
            "reading": (
                "code control expands over the whole closure of the controlled node — owning "
                "the code exercises everything the code is authorized to exercise. Gate control "
                "expands only through edges it passes a test on, and the test is no longer the "
                "label-presence test that walked any edge whose label named a scope at all. The "
                "two scope kinds are tested differently and the two tests are not equally strong. "
                "A `roles N` edge is walked where function_principals.details.trace[].selector, "
                "joined to effective_functions.selector at the destination, names the functions "
                "role N licenses there — a positive witness of what the hop delivers, published "
                "per finding as reach_licensed_functions. A state-variable edge is tested by a "
                "SAME-KIND BOUND, which is weaker and is not a conferral witness: the gate's own "
                "function is observed (effective_functions.state_writes, origin=body) to rewrite "
                "a variable of that name on ITS contract, while the edge's label names the "
                "authority slot on the DESTINATION's, so the match is a name match across two "
                "contracts' storage and witnesses no composition step. What it does is REFUSE "
                "hops whose authority is of a different kind from the one the gate seizes "
                "('hook', 'vault', 'roleRegistry'); the same-kind hops that survive it walk on no "
                "more evidence than the label-presence test gave them. A refused hop is NOT "
                "disproved: whether it composes anyway turns on the intermediate node's own "
                "function surface, and this plane DOES NOT CONSULT IT — a refusal here is "
                "therefore a join not performed, and nothing in it says the surface that would "
                "answer the question is absent. The join that would decide it is the intermediate "
                "node's own functions against its outbound targets "
                "(effective_functions.sinks/effect_targets and the external_call_target edges "
                "CONTROL_RELATIONS excludes). Until it runs the hop is withheld as "
                "not_determined. That join NOW RUNS, under act_as_composition, and it is worth "
                "being exact about what it decides: it bounds the MAGNITUDE of a licensed hop, "
                "not the membership of the walk. A hop with no act-as witness is still walked as "
                "reach — the licence witnessed it — and simply carries no composed dollars. "
                "Widening the reach on the same join is a separate change nobody has argued for "
                "here. Both classes are bounded by the destination's own caller "
                "conditions. Every hop neither class could establish is published per finding as "
                "reach_hops_not_determined, never dropped, and reach_withheld_behind_hops sizes "
                "the subtree each withheld frontier hop hides"
            ),
        },
        "unpriced_positions": value_plane.unpriced_positions,
        "exposure_gaps": exposure_gaps,
        # How much of the perimeter grade_exposure was measured over. Without
        # it the ratio's numerator (a few findings) and its denominator (the
        # whole priced perimeter) are not comparable quantities, and the figure
        # reads as a measurement of safety rather than of coverage.
        "exposure_coverage": exposure_coverage,
        # The sheet-ceiling population at the document level. Every entry it
        # counts is published per row too, and it is still worth assembling
        # once: these dollars are the one class of published magnitude that is
        # deliberately absent from exposure_usd, so a consumer that reads only
        # the grade figures would have no way to see how much money the model
        # bounded from above and then declined to charge. Its credited-signal
        # count is the confidence pass's own, not a second derivation of it.
        "sheet_ceilings": _sheet_ceiling_totals(
            findings,
            subsumed,
            confidence["reach_magnitude_signals"]["sheet_ceiling_by_capability"],
        ),
        "principal_units": units.published_units(),
        "safe_keyset_overlaps": units.overlaps,
        "unit_evidence_scope": (
            "principal_units and safe_keyset_overlaps cover only the Safes reachable "
            "from claim-bearing signals: a Safe that gates nothing this scorer scored "
            "is absent from the union-find, so an overlap it would have merged is "
            "not_determined rather than proven absent"
        ),
        "upgrade_history": P.load_upgrade_provenance(session, protocol_id),
        "unconsumed_reach_relations": P.unconsumed_reach_relations(session, protocol_id),
        "ledgers": P.load_ledgers(session, protocol_id),
        "audit_posture": P.load_audit_posture(session, protocol_id, value_plane),
        "perimeter": perimeter_detail,
        "signal_scope": (
            "a signal is keyed on a CAPABILITY, so a function carrying no claim produces "
            "none: its earned empty caller set and its one_shot latch witness are outside "
            "this document. That is a distillation gap, never a proven absence"
        ),
        "determinism": (
            "every query carries a total ORDER BY and every sort a total tiebreak; "
            "the same DB state yields an identical document modulo computed_at"
        ),
    }

    # The three grade figures stand or fall together, and so does everything
    # derived from them. An exposure ratio with no priced denominator is not a
    # 100 — it is a quantity that was never measured — so a protocol with
    # findings but no priced value publishes the findings and parks every
    # derived number under provenance instead of serving it beside a withheld
    # grade.
    scored = bool(findings) and grade_exposure is not None
    if not scored:
        withheld_rows = [
            {
                "principal_unit": finding["principal_unit"],
                "capability": finding["capability"],
                "net_points_lambda": finding.pop("net_points_lambda", None),
                "exposure_usd": finding.pop("exposure_usd", None),
            }
            for finding in findings
        ]
        if findings:
            provenance["grade_withheld"] = {
                "grade_lambda_computed": grade_lambda,
                "confidence_pct_computed": confidence.pop("pct", None),
                "exposure_usd_computed": exposure_usd,
                "per_finding": withheld_rows,
                "reason": "no priced value in the perimeter, so the exposure denominator is not_determined",
            }
        else:
            confidence.pop("pct", None)

    return ScoreDocument(
        protocol_id=protocol_id,
        model_version=MODEL_VERSION,
        computed_at=computed_at or datetime.now(timezone.utc),
        trigger=trigger,
        trigger_job_id=trigger_job_id,
        perimeter_state=perimeter,
        grade_state=GRADE_STATE_COMPUTED if scored else GRADE_STATE_NOT_DETERMINED,
        grade_lambda=grade_lambda if scored else None,
        grade_exposure=grade_exposure if scored else None,
        confidence_pct=confidence.get("pct") if scored else None,
        findings=findings,
        earned_negatives=sorted(earned_negatives, key=lambda e: (e["entity"], e["function"], e["capability"])),
        warnings=_summarise_warnings(warnings),
        model_parameters={**K.model_parameters(), "confidence_detail": confidence},
        provenance={**provenance, "subsumed_rows": subsumed, "exposure_usd": exposure_usd if scored else None},
        uncalibrated_arms=K.UNCALIBRATED_ARMS,
        execution_evidence_faults=execution_faults,
    )


def _row_for(
    rows: dict[tuple[str, str, str], _Row],
    unit: str,
    capability: str,
    path: str,
    weakness: float,
    label: str,
    kind: str,
    address: str,
) -> _Row:
    """The row for one (unit, capability, ACCESS PATH), at its weakest gate.

    The path is part of the key because a unit can hold the same capability
    through paths that cost different things: a Safe that also proposes-and-
    executes on a timelock reaches the timelock's contracts only by paying the
    delay, and one max-weakness row would charge that delayed value at the
    Safe's undelayed rung. Within one path the weakest gate still wins (inv.5),
    which is what keeps two merged Safes one power rather than two.
    """
    key = (unit, capability, path)
    row = rows.get(key)
    if row is None:
        row = _Row(unit=unit, capability=capability, path=path)
        rows[key] = row
    if weakness > row.weakness or not row.weakest_label:
        row.weakness = weakness
        row.weakest_label = label
        row.principal_kind = kind
        row.weakest_address = address
    row.principal_addresses.add(address)
    # The member's OWN rung, kept beside the unit's weakest: a merged Safe unit
    # publishes one reach union, and pricing an entity only the 4/8 member
    # reaches at the 3/7 member's rung charges a coalition nobody proved.
    previous = row.member_gate.get(address)
    if previous is None or weakness > previous[0]:
        row.member_gate[address] = (weakness, label, kind)
    return row


# ---------------------------------------------------------------- gate reads


def _malformed_gates(signal: FunctionSignal) -> list[str]:
    """Gate envelopes this fold refuses to read, by name.

    A state outside the gate's closed vocabulary, or a numeric payload that is
    not a finite number, is a row this fold cannot score honestly.
    """
    bad: list[str] = []
    for name in REQUIRED_GATES + REQUIRED_GATES_BY_CLAIM.get(signal.claim_id, ()):
        if name not in signal.gate_inputs:
            bad.append(f"{name}(absent)")
    for name, raw in sorted(signal.gate_inputs.items()):
        expected = GATE_PROVEN_TOKENS.get(name)
        if expected is None:
            continue
        try:
            tri = Tri.from_json(raw)
        except ValueError:
            bad.append(name)
            continue
        if tri.state == NOT_DETERMINED:
            continue
        if tri.state not in expected:
            bad.append(name)
            continue
        if not _payload_has_shape(name, tri.value):
            bad.append(name)
    return bad


def _payload_has_shape(name: str, value: Any) -> bool:
    """Whether a proven gate payload is the shape its consumers walk."""
    shape = GATE_PAYLOAD_SHAPES.get(name)
    if shape is None:
        return True
    if shape == "number":
        return _is_number(value)
    if shape == "bool":
        return isinstance(value, bool)
    if shape == "string":
        return isinstance(value, str)
    if shape == "object":
        return isinstance(value, dict)
    if shape == "string_list":
        return isinstance(value, list) and all(isinstance(item, str) for item in value)
    if shape == "principal_ref_list":
        return isinstance(value, list) and all(_is_principal_ref(item) for item in value)
    return False


def _is_principal_ref(entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    raw_id = entry.get("function_principal_id")
    if isinstance(raw_id, bool) or not isinstance(raw_id, int):
        return False
    for key in ("chain", "address"):
        if key in entry and entry[key] is not None and not isinstance(entry[key], str):
            return False
    return True


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value))


def _gate(signal: FunctionSignal, name: str) -> Tri[Any]:
    """One gate, read on its EXACT proven token. Never "is not not_determined".

    A state the gate's vocabulary does not name is returned as
    ``not_determined``: an unrecognised token is a witness this fold cannot
    vouch for, and reading it as the positive branch is how a withheld arm
    publishes an earned one.
    """
    try:
        tri = signal.gate_input(name)
    except KeyError:
        # ``_malformed_gates`` has already withheld any row whose required gates
        # are missing; this arm keeps an incidental read from raising out of the
        # fold rather than inventing a value.
        return Tri.not_determined()
    expected = GATE_PROVEN_TOKENS.get(name, ())
    if tri.state == NOT_DETERMINED or tri.state in expected:
        if name in NUMERIC_GATES and tri.is_determined and not _is_number(tri.value):
            return Tri.not_determined()
        return tri
    return Tri.not_determined()


# ---------------------------------------------------------------- principals


class _UnitResolver:
    """Principal units: per (chain, address), with the two licensed collapses.

    Safes that can ACT AS each other are one unit — independence is a property of
    owner KEY SETS, and two Safes sharing enough owners are one power. A timelock
    whose proposer-executor is a Safe collapses into that Safe: upgrade-by-
    timelock is a subset of exec-by-proposer, so two rows would charge the same
    value twice. The collapse needs BOTH halves proven — proposing without
    executing is not acting as the timelock — and neither collapse ever crosses a
    chain, because same-address is not proof of same owner set.
    """

    def __init__(
        self,
        signals: list[FunctionSignal],
        principal_facts: dict[int, P.PrincipalFacts],
        role_floors: dict[tuple[str, str, str], dict[str, Any]],
    ) -> None:
        self._facts = principal_facts
        self._role_floors = role_floors
        by_key: dict[str, list[P.PrincipalFacts]] = defaultdict(list)
        for facts in sorted(principal_facts.values(), key=lambda f: f.key):
            if facts.resolved_type == "safe" and facts.owners:
                by_key[facts.key].append(facts)
        # Last row wins, exactly as before: which contradictory owner set to adopt
        # is an open ruling (R17), and this fold does not arbitrate it. What it
        # will not do is arbitrate SILENTLY — a Safe whose witnesses disagree
        # publishes the disagreement beside the set the merge decision used.
        self._safe_by_key = {key: rows[-1] for key, rows in by_key.items()}
        self.owner_set_contradictions = [
            {
                "safe": key,
                "adopted_owner_set": sorted(rows[-1].owners),
                "adopted_k_of_n": (
                    f"{rows[-1].threshold}/{len(rows[-1].owners)}"
                    if rows[-1].threshold is not None
                    else f"k not_determined/{len(rows[-1].owners)}"
                ),
                "witnesses": [
                    {
                        "function_principal_id": row.function_principal_id,
                        "owners": sorted(row.owners),
                        "threshold": row.threshold,
                    }
                    for row in sorted(rows, key=lambda r: r.function_principal_id)
                ],
                "basis": (
                    "function_principals rows disagree on this Safe's owner set; the adopted "
                    "row is the one this fold read, NOT an adjudication that the others are wrong"
                ),
            }
            for key, rows in sorted(by_key.items())
            if len({frozenset(row.owners) for row in rows}) > 1
        ]
        self._parent = {key: key for key in self._safe_by_key}
        self.overlaps: list[dict[str, Any]] = []
        self._union_overlapping_safes()
        self._proposers = self._timelock_proposer_executors(signals)
        self._members: dict[str, set[str]] = defaultdict(set)

    def _find(self, key: str) -> str:
        while self._parent[key] != key:
            self._parent[key] = self._parent[self._parent[key]]
            key = self._parent[key]
        return key

    def _union_overlapping_safes(self) -> None:
        keys = sorted(self._safe_by_key)
        for i, a in enumerate(keys):
            for b in keys[i + 1 :]:
                left, right = self._safe_by_key[a], self._safe_by_key[b]
                if left.chain != right.chain:
                    continue
                shared = left.owners & right.owners
                if not shared:
                    continue
                # An unread threshold cannot license a merge: "these two Safes are
                # one power" needs both thresholds proven, and a sentinel standing
                # in for one would publish a coalition size nobody measured.
                if left.threshold is None or right.threshold is None:
                    self.overlaps.append(
                        {
                            "a": a,
                            "b": b,
                            "shared_owners": len(shared),
                            "merged": False,
                            "basis": "threshold_not_determined_on_at_least_one_side",
                        }
                    )
                    continue
                k_left, k_right = left.threshold, right.threshold
                can_act = len(shared) >= max(k_left, k_right)
                block_left = len(left.owners) - k_left + 1
                block_right = len(right.owners) - k_right + 1
                self.overlaps.append(
                    {
                        "a": a,
                        "b": b,
                        "a_k_of_n": f"{k_left}/{len(left.owners)}",
                        "b_k_of_n": f"{k_right}/{len(right.owners)}",
                        "shared_owners": len(shared),
                        "shared_can_act_as_both": can_act,
                        "shared_can_block_both": len(shared) >= max(block_left, block_right),
                        "min_coalition_to_act_as_both": max(k_left, k_right) if can_act else None,
                        "merged": can_act,
                        "basis": "owner_key_set_intersection",
                    }
                )
                if can_act:
                    root_a, root_b = self._find(a), self._find(b)
                    if root_a != root_b:
                        self._parent[root_b] = root_a
        self.overlaps.sort(key=lambda o: (o["a"], o["b"]))

    def _timelock_proposer_executors(self, signals: list[FunctionSignal]) -> dict[str, dict[str, Any]]:
        """The weakest Safe proven able to BOTH propose and execute on a timelock.

        Both halves are required because the collapse asserts the Safe can act as
        the timelock. A propose-only witness proves the right to start a delayed
        action, not the right to complete one, and treating it as the collapse
        would re-price every timelock-gated dollar at the proposer's undelayed
        weakness on the strength of a witness that never mentioned execution.
        """
        by_role: dict[str, dict[str, set[str]]] = defaultdict(lambda: {"schedule": set(), "execute": set()})
        facts_by_key: dict[str, P.PrincipalFacts] = {}
        for signal in sorted(signals, key=lambda s: (s.chain, s.deployment_address, s.selector, s.claim_id)):
            role = {"timelock.schedule": "schedule", "timelock.execute": "execute"}.get(signal.claim_id)
            if role is None:
                continue
            timelock_key = entity_key(signal.chain, signal.deployment_address)
            for ref in signal.principal_refs:
                facts = self._facts.get(int(ref.function_principal_id))
                if facts is None or facts.resolved_type != "safe" or not facts.owners:
                    continue
                by_role[timelock_key][role].add(facts.key)
                facts_by_key[facts.key] = facts

        out: dict[str, dict[str, Any]] = {}
        for timelock_key in sorted(by_role):
            both = sorted(by_role[timelock_key]["schedule"] & by_role[timelock_key]["execute"])
            best: dict[str, Any] | None = None
            for safe_key in both:
                facts = facts_by_key[safe_key]
                # inv.5 is the WEAKEST path. An unread threshold cannot lose that
                # comparison: it sorts first, and is then priced at the uncredited
                # rung rather than at a ratio nobody measured.
                rank = (0, 0.0) if facts.threshold is None else (1, facts.threshold / len(facts.owners))
                candidate = {
                    "key": safe_key,
                    "k": facts.threshold,
                    "n": len(facts.owners),
                    "rank": rank,
                }
                if best is None or candidate["rank"] < best["rank"]:
                    best = candidate
            if best is not None:
                out[timelock_key] = best
        return out

    def unit_for(self, facts: P.PrincipalFacts) -> str:
        key = facts.key
        if facts.resolved_type == "timelock":
            proposer = self._proposers.get(key)
            if proposer:
                key = str(proposer["key"])
        if key in self._parent:
            # The unit is named by its LOWEST member key, not by whichever root
            # the union order happened to leave: a union-find root is an
            # implementation artefact, and naming a unit with one would make the
            # same set of Safes carry different identities across runs.
            root = self._find(key)
            members = {member for member in self._parent if self._find(member) == root}
            unit = min(members)
            self._members[unit] |= members
            return unit
        self._members[key].add(key)
        return key

    def published_units(self) -> dict[str, Any]:
        """The unit memberships this fold folded, as the document's own evidence.

        A unit id is only meaningful beside the members it collapsed: without
        them a consumer cannot tell a re-labelled unit from a re-keyed one, and
        cannot check the inv.13 collapse that removed a double charge.
        """
        return {
            "members": {unit: sorted(members) for unit, members in sorted(self._members.items())},
            "timelock_collapses": {
                timelock: {
                    "into": entry["key"],
                    "proposer_k_of_n": (f"{entry['k']}/{entry['n']}" if entry["k"] is not None else "not_determined"),
                    "basis": "proven proposer AND executor",
                }
                for timelock, entry in sorted(self._proposers.items())
            },
            "owner_set_contradictions": self.owner_set_contradictions,
        }

    def proposer_for(self, facts: P.PrincipalFacts) -> dict[str, Any] | None:
        return self._proposers.get(facts.key)

    def path_for(self, facts: P.PrincipalFacts) -> str:
        """How this principal reaches the unit's capability: directly, or via a delay."""
        if facts.resolved_type == "timelock" and facts.key in self._proposers:
            return f"via_timelock:{facts.key}"
        return "direct"

    def weakness_for(
        self, facts: P.PrincipalFacts, *, recovery_proven_independent: bool = False
    ) -> tuple[float | None, str, str, list[str]]:
        notes: list[str] = []
        if facts.resolver_bases:
            weak = [b for b in facts.resolver_bases if K.resolver_basis_tier(b) == K.WEAKEST_RESOLVER_BASIS_TIER]
            if weak:
                notes.append("resolver_basis_convention:" + ",".join(sorted(weak)))

        if facts.resolved_type == "eoa":
            weakness, label, kind = K.WEAKNESS_EOA, "EOA", "eoa"
        elif facts.resolved_type == "safe":
            weakness, label, notes = _safe_weakness(facts, notes, recovery_proven_independent)
            kind = "safe"
        elif facts.resolved_type == "timelock":
            weakness, label, notes = self._timelock_weakness(facts, notes)
            kind = "timelock"
        elif facts.resolved_type == "contract":
            # "An EOA controls the gating CONTRACT" is not "an EOA can call this
            # function": the gating contract may impose its own conditions. The
            # hop is a confidence fact, never this row's weakness.
            return None, "contract", "contract", notes
        else:
            return None, facts.resolved_type or "unresolved", "unknown", notes

        raised = self._role_breadth(facts)
        if raised is not None and raised > weakness:
            notes.append(f"role_holder_floor_raises_breadth:{raised}")
            weakness = raised
        return weakness, label, kind, notes

    def _timelock_weakness(self, facts: P.PrincipalFacts, notes: list[str]) -> tuple[float, str, list[str]]:
        discount = K.delay_discount(facts.delay_seconds)
        proposer = self.proposer_for(facts)
        if discount is None:
            notes.append("timelock_delay_not_determined")
            return K.WEAKNESS_TIMELOCK_UNDETERMINED, "timelock(delay not_determined)", notes
        # Reached only where the discount resolved, which requires a read delay.
        delay_seconds = float(facts.delay_seconds) if facts.delay_seconds is not None else 0.0
        days = int(delay_seconds // 86400)
        if delay_seconds == 0:
            # A proven ZERO delay is proven-absent protection, not an unread one.
            # It earns no discount and does not land on the undetermined rung.
            notes.append("timelock_delay_proven_zero:no_protection")
            if proposer is None:
                return K.WEAKNESS_SAFE_UNCREDITED, "timelock(0d, proposer not_determined)", notes
            base = K.quorum_weakness(proposer["k"], proposer["n"], credit_withheld=False)
            notes.append(f"proposer={_kn(proposer)}")
            return base, f"timelock 0d via {_kn(proposer)}", notes
        if proposer is None:
            # A proven delay whose proposer-executor set is undetermined is not
            # proven protection, so the delay earns no discount.
            notes.append("timelock_proposer_not_determined:no_delay_credit")
            return K.WEAKNESS_TIMELOCK_UNDETERMINED, f"timelock {days}d(proposer not_determined)", notes
        base = K.quorum_weakness(proposer["k"], proposer["n"], credit_withheld=False)
        notes.append(f"delay_discount={discount};proposer={_kn(proposer)}")
        return round(base * discount, 4), f"timelock {days}d via {_kn(proposer)}", notes

    def _role_breadth(self, facts: P.PrincipalFacts) -> float | None:
        """A proven holder floor above one is proven BREADTH. It may only raise."""
        for registry, role_hash in facts.role_bindings:
            entry = self._role_floors.get((facts.chain, registry, role_hash))
            if entry and entry["holders_floor"] > 1:
                return K.ROLE_BREADTH_MULTI_HOLDER_WEAKNESS
        return None


def _kn(proposer: dict[str, Any]) -> str:
    """A proposer's k/n, or the honest refusal. Never a fabricated ratio."""
    return f"{proposer['k']}/{proposer['n']}" if proposer["k"] is not None else "k not_determined"


def _safe_weakness(
    facts: P.PrincipalFacts, notes: list[str], recovery_proven_independent: bool
) -> tuple[float, str, list[str]]:
    """A Safe's weakness from its PROVEN k and n, or the uncredited rung.

    An unread owner set is not an n. Backfilling n from k publishes a k-of-k Safe
    — the strongest rung on the ladder — out of a witness that never existed, and
    prints the fabricated ratio as the finding's own principal.
    """
    if not facts.owners:
        notes.append("safe_owner_set_not_determined:kn_uncomputable")
        label = "Safe (owners not_determined)" if facts.threshold is None else f"Safe k={facts.threshold}/n?"
        return K.WEAKNESS_SAFE_UNCREDITED, label, notes
    n = len(facts.owners)
    weakness = K.quorum_weakness(
        facts.threshold,
        n,
        credit_withheld=facts.protection_credit_withheld,
        waive_single_signer_cliff=recovery_proven_independent,
    )
    if facts.protection_credit_withheld:
        notes.append(f"safe_kn_credit_withheld:{facts.protection_basis}")
    label = f"Safe {facts.threshold}/{n}" if facts.threshold is not None else f"Safe k?/{n}"
    return weakness, label, notes


def _recovery_refs(signals: list[FunctionSignal]) -> list[Any]:
    """Principal references named by pause recovery gates, so the fold can read them."""

    @dataclass(frozen=True)
    class _Ref:
        function_principal_id: int
        chain: str
        address: str

    out: list[Any] = []
    for signal in signals:
        # Runs before the per-signal gate check in the main loop, so it repeats
        # it: a malformed payload must not be walked HERE either.
        if signal.claim_id != "pause.set" or _malformed_gates(signal):
            continue
        gate = _gate(signal, "freeze_recovery_principals")
        if not gate.is_determined or not isinstance(gate.value, list):
            continue
        for entry in gate.value:
            if _is_principal_ref(entry):
                out.append(
                    _Ref(
                        function_principal_id=int(entry["function_principal_id"]),
                        # The gate's entries are minted beside the pause signal on
                        # the same contract, so the chain is the same fact, not a
                        # substitute for an unread one. A JSONB null falls back to
                        # that same fact rather than stringifying to "None".
                        chain=str(entry.get("chain") or signal.chain),
                        address=str(entry.get("address") or ""),
                    )
                )
    return out


# ---------------------------------------------------------------- severity


def _fold_severity(
    signal: FunctionSignal,
    principal: P.PrincipalFacts | None,
    principal_facts: dict[int, P.PrincipalFacts],
    warnings: list[dict[str, Any]],
) -> tuple[float, tuple[str, ...], set[str]]:
    """The distilled severity, plus the components only the fold can prove.

    Per PRINCIPAL, not per function: whether a freeze is recoverable is a
    property of the freezing key set against the recovery key set, so evaluating
    it once over the union of a function's principals would charge a key set for
    an overlap another principal contributed.
    """
    severity = signal.severity.require(SEVERITY_STATE_PROVEN)
    basis = tuple(signal.severity_basis)
    notes: set[str] = set()
    if signal.claim_id != "pause.set" or principal is None:
        return severity, basis, notes

    verdict, coalition, note = _keyset_independence(signal, principal, principal_facts)
    if verdict is False:
        # PROVEN: this key set can freeze and also deny the recovery quorum.
        severity = max(severity, K.FREEZE_SUSTAINABLE)
        basis = basis + ("freeze_keyset_not_independent",)
        warnings.append(
            _warning(
                "freeze_keyset_not_independent",
                signal,
                "this key set can freeze AND deny the recovery quorum",
                min_coalition_to_sustain=coalition,
            )
        )
    elif verdict is None:
        # Every undetermined arm — no recovery claim, an unresolved recovery
        # principal, an unread freezing key set — leaves the rung where the
        # capability's proven existence put it. Raising here would move severity
        # on an absent witness; lowering would credit one. The question itself is
        # published instead.
        notes.add(note)
        basis = basis + ("freeze_recovery_independence_not_determined",)
        warnings.append(_warning("freeze_recovery_independence_not_determined", signal, note))
    else:
        # PROVEN independence: the credited rung, which equals the existence rung
        # today, so what changes is the basis rather than the number.
        severity = min(severity, K.FREEZE_KEYSET_RECOVERABLE)
        notes.add(note)
        basis = basis + ("freeze_keyset_independent",)
    return severity, basis, notes


def _keyset_independence(
    signal: FunctionSignal, principal: P.PrincipalFacts, principal_facts: dict[int, P.PrincipalFacts]
) -> tuple[bool | None, int | None, str]:
    """Is the recovery quorum independent of the freezing one, in KEYS?

    Independence is a property of owner key sets: P and U are independent iff
    ``|owners(U) \\ owners(P)| >= threshold(U)``. Comparing principal ADDRESSES
    publishes a protective credit for a configuration where a handful of keys
    freeze the protocol and hold it — and an address stands in for a key set only
    where the principal IS a single key, i.e. an EOA. For every other type an
    unread owner set makes the test uncomputable, not favourable.
    """
    if principal.owners:
        pauser_owners = principal.owners
    elif principal.resolved_type == "eoa":
        pauser_owners = frozenset({principal.address})
    else:
        return None, None, "pauser_key_set_not_determined"

    gate = _gate(signal, "freeze_recovery_principals")
    if not gate.is_determined or not isinstance(gate.value, list):
        return None, None, "recovery_path_not_determined_no_unset_claim"
    saw_safe = False
    best: int | None = None
    for entry in sorted((e for e in gate.value if _is_principal_ref(e)), key=lambda e: str(e.get("address"))):
        facts = principal_facts.get(int(entry["function_principal_id"]))
        if facts is None or facts.resolved_type != "safe" or not facts.owners or facts.threshold is None:
            continue
        saw_safe = True
        residual = len(facts.owners - pauser_owners)
        if residual >= facts.threshold:
            return True, None, f"keyset_independent:{residual}>={facts.threshold}"
        block = max(1, len(facts.owners) - facts.threshold + 1)
        best = block if best is None else min(best, block)
    if saw_safe:
        return False, best, "keyset_dependent"
    return None, None, "recovery_principal_unresolved"


# ---------------------------------------------------------------- value fold


def _instance(
    signal: FunctionSignal, severity: float, basis: tuple[str, ...], principal_address: str = ""
) -> _Instance:
    magnitude = _gate(signal, "reach_magnitude_usd")
    pricing_blocked = None
    native_only = False
    asset_identity_undecidable = False
    if signal.claim_id == "flow.out":
        if _gate(signal, "token_identity").is_determined:
            # Exactly one NON-FUNGIBLE token moves: pricing the row off a
            # fungible balance sheet is forbidden, not merely imprecise.
            pricing_blocked = "token_identity(non-fungible; pricing forbidden)"
        asset_class = _gate(signal, "asset_class")
        native_only = asset_class.is_determined and asset_class.value == "native_only"
        # The W2 pricing precondition: single-asset pricing is licensed only by a
        # decidable token identity. Undecidable ⇒ the unpriced branch, never the
        # entity's whole fungible sheet read as this call's magnitude.
        asset_identity_undecidable = (
            asset_class.is_determined
            and asset_class.value in SINGLE_ASSET_CLASSES
            and not _gate(signal, "asset_identity").is_determined
        )
    return _Instance(
        signal=signal,
        severity=severity,
        severity_basis=basis,
        entity_keys=signal.value_entity_keys,
        magnitude=magnitude,
        value_bound=signal.value_bound,
        pricing_blocked=pricing_blocked,
        native_only=native_only,
        asset_identity_undecidable=asset_identity_undecidable,
        principal_address=principal_address,
    )


def _attach(row: _Row, signal: FunctionSignal, instance: _Instance, notes: set[str]) -> None:
    # The burn sentinel is refused as a REACH key here, one admission short of the
    # walk: ``msg.sender != 0x0``, so nothing routes value through it and a
    # repoint witness that names it has proved no reach. The confidence perimeter
    # refuses it on the same rule; this is the value side of that discipline.
    kept = tuple(key for key in instance.entity_keys if not P.is_zero_key(key))
    if len(kept) != len(instance.entity_keys):
        row.zero_reach_keys_refused += len(instance.entity_keys) - len(kept)
        row.notes.add("zero_address_reach_key_refused")
        if not kept:
            # Every reach key this instance carried was the sentinel, so it now
            # witnesses nothing. Dropping it silently would read as "this call
            # reaches no priced entity" — an earned negative it never earned.
            row.zero_reach_stripped.append(
                {
                    "function": signal.function_name,
                    "entity": entity_key(signal.chain, signal.deployment_address),
                    "why": "every_reach_key_was_the_zero_address(refused; reach not_determined)",
                }
            )
        instance.entity_keys = kept
    row.instances.append(instance)
    row.seeds.add(entity_key(signal.chain, signal.deployment_address))
    row.tiers.add(signal.witness_tier)
    row.notes.update(signal.witness_notes)
    row.notes.update(notes)
    row.citations.extend(signal.citations)


def _member_weakness(
    row: _Row,
    per_entity: dict[str, float],
    value_plane: P.ValuePlane,
    closure: P.ControlClosure,
    conditions: P.ConditionPlane,
    conferral: P.ConferralPlane,
    act_as: P.ActAsPlane,
    magnitudes: dict[tuple[str, str], _DestinationMagnitude],
    admission: _AdmissionPlanes,
) -> tuple[dict[str, float], float, tuple[str, str, str]]:
    """A merged unit's weakness, per REACHED ENTITY (inv. 5).

    ``_row_for`` keeps the max weakness over a merged Safe unit's members while
    the row folds the UNION of their reach, with no tie between a member's rung
    and the entities that member reaches — so value only the 4/8 member can move
    is published at the 3/7 member's rung, a coalition nobody proved.

    inv. 5's weakest path is the weakest path TO THAT ENTITY: entity ``e`` is
    priced at the max over ONLY the members proven to reach ``e``. The row still
    publishes a single weakness against a union no single member reaches, so that
    union is priced at **the hardest rung among the contributing members** — the
    ``min`` over the per-entity rungs. That is NOT the overlap record's
    ``min_coalition_to_act_as_both``: that field is ``max(k)``, and weakness is
    keyed on ``k/n``, so a 3/4 member (0.20) and a 5/20 member (0.55) put the
    coalition size on the 5/20 Safe while this rung is the 3/4's 0.20. The
    hardest rung is the deliberate under-claim — inv. 5 forbids pricing a union
    at a rung no contributing member has to clear. Naming a member's reach needs
    the member's own witness, so a row whose instances cannot be attributed to a
    member keeps the unit-level rung rather than inventing an attribution.
    """
    unchanged = ({}, row.weakness, (row.weakest_label, row.principal_kind, row.weakest_address))
    if len(row.member_gate) < 2 or not per_entity:
        return unchanged
    by_member: dict[str, list[_Instance]] = defaultdict(list)
    for instance in row.instances:
        if instance.principal_address not in row.member_gate:
            return unchanged
        by_member[instance.principal_address].append(instance)

    reach_by_member: dict[str, set[str]] = {}
    for address, instances in by_member.items():
        probe = _Row(unit=row.unit, capability=row.capability, path=row.path)
        probe.instances = instances
        # Reach is MEMBERSHIP, so it is read off ``.reach`` and never off the
        # value map: W2b's per-call magnitude cap scales what a member is charged
        # and can empty ``per_entity`` outright, but it moves no entity out of
        # what the member provably reaches.
        reached = _row_value(probe, value_plane, closure, conditions, conferral, act_as, magnitudes, admission).reach
        reach_by_member[address] = reached

    weakness_by_entity: dict[str, float] = {}
    holders_by_entity: dict[str, list[str]] = {}
    for key in sorted(per_entity):
        holders = sorted(a for a, reached in reach_by_member.items() if key in reached)
        if not holders:
            # The union carries an entity no single member's fold reproduces.
            # That is an attribution this function cannot witness, so the row
            # keeps the unit rung rather than pricing it at a guess.
            return unchanged
        holders_by_entity[key] = holders
        weakness_by_entity[key] = max(row.member_gate[a][0] for a in holders)

    if len({*weakness_by_entity.values(), row.weakness}) == 1:
        return unchanged
    binding_key = min(weakness_by_entity, key=lambda k: (weakness_by_entity[k], k))
    published = weakness_by_entity[binding_key]
    binding = max(holders_by_entity[binding_key], key=lambda a: (row.member_gate[a][0], a))
    _, label, kind = row.member_gate[binding]
    return weakness_by_entity, published, (label, kind, binding)


CITATION_CAP = 8
# A citation that points AT evidence: a transcript pointer, a verdict, the block
# a reading was pinned to. Everything else is a field restatement, and a
# ``reading`` key marks the ones that are prose about how to read a field rather
# than a pointer to anything.
_CITATION_EVIDENCE_KEYS = ("transcript_ptr", "verdict", "block_source")


def _cited(citations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The row's citations, evidence first, capped for display.

    The cap is a display bound and the eviction it causes is arbitrary, so the
    order it evicts in must not be. A citation pointing at a transcript is the
    one a reader can check; a prose ``reading`` restating how to read a field is
    not, and it evicted two transcript pointers off a shipped row. Stable within
    each tier, so the population order still decides among equals.
    """

    def rank(citation: dict[str, Any]) -> int:
        if not isinstance(citation, dict):
            return 1
        if any(key in citation for key in _CITATION_EVIDENCE_KEYS):
            return 0
        return 2 if "reading" in citation else 1

    return sorted(citations, key=rank)[:CITATION_CAP]


def _aggregate(
    rows_by_key: dict[tuple[str, str, str], _Row],
    value_plane: P.ValuePlane,
    closure: P.ControlClosure,
    conditions: P.ConditionPlane,
    conferral: P.ConferralPlane,
    act_as: P.ActAsPlane,
    magnitudes: dict[tuple[str, str], _DestinationMagnitude],
    admission: _AdmissionPlanes,
    units: _UnitResolver,
    composed_signals: set[tuple[Any, ...]],
    ceiling_signals: set[tuple[Any, ...]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    warnings: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    for key in sorted(rows_by_key):
        row = rows_by_key[key]
        if not row.instances:
            continue
        valued = _row_value(row, value_plane, closure, conditions, conferral, act_as, magnitudes, admission)
        composed_signals.update(valued.composed_signals)
        # Rolled up beside the composed set and never merged into it. Both name
        # signals whose magnitude question the FOLD answered rather than the
        # signal, and they answered it with different evidence — a destination's
        # own flow.out witness against a balance observation — so a consumer
        # crediting either has to be able to say which one it credited.
        ceiling_signals.update(valued.ceiling_signals)
        per_entity, value_usd, undetermined = valued.per_entity, valued.total_usd, valued.undetermined
        value_basis = valued.basis
        if row.zero_reach_stripped:
            undetermined = undetermined + row.zero_reach_stripped
            value_basis += f"; {len(row.zero_reach_stripped)} instance(s) reached only the refused zero address"
        # A priced total over an entity that also holds assets the priced sheet
        # never covered is a FLOOR over that entity, not its value: an instance
        # that answered is not the same fact as an entity that was answered.
        partially_priced = _partially_priced_entities(value_plane, valued.reach)
        # Coverage alone decides nothing about direction. A contribution that is
        # itself an extraction ceiling cannot be summed into a floor because
        # OTHER contributions are missing, so the two axes are read together.
        direction = _bound_direction(
            value_usd,
            frozenset(per_entity),
            valued.ceiling_entities,
            bool(undetermined or partially_priced),
            # The withheld-reach block is ALWAYS a dict — it carries its own
            # reading even when nothing was withheld — so its counts are what is
            # read here and never its truthiness.
            bool(
                valued.hops_not_determined
                or valued.withheld_behind_hops.get("hops")
                or valued.withheld_behind_hops.get("entities")
            ),
            valued.non_attributed_entities,
        )
        # Only a row that HAS a total and something in it to grade has a
        # direction to explain. A row whose value is not_determined publishes
        # that word as its basis, and a proven_no_reach row publishes an earned
        # negative consumers branch on by name — neither is a bound claim.
        #
        # Both writers live HERE and not in :func:`_row_value` for one reason:
        # the string names a direction, and the direction is not known until the
        # attribution axis has been read beside the coverage one. A basis built
        # from coverage alone said ">= proven floor" beside a header refusing to
        # publish a floor.
        if valued.ceiling_entities:
            value_basis = _ceiling_bearing_basis(
                direction,
                per_entity,
                valued.ceiling_entities - valued.sheet_ceiling_entities,
                valued.sheet_ceiling_entities,
                undetermined,
                partially_priced,
                valued.proven_no_reach,
                row.zero_reach_stripped,
                valued.hops_not_determined,
                valued.withheld_behind_hops,
                valued.composed_magnitudes,
                value_plane,
            )
        elif value_usd is not None and (undetermined or partially_priced):
            value_basis = _coverage_bearing_basis(
                direction,
                per_entity,
                undetermined,
                partially_priced,
                valued.non_attributed_entities,
                valued.proven_no_reach,
                row.zero_reach_stripped,
            )
        is_floor = direction == BOUND_DIRECTION_FLOOR
        weakness_by_entity, weakness, weakest = _member_weakness(
            row, per_entity, value_plane, closure, conditions, conferral, act_as, magnitudes, admission
        )
        severity = max(instance.severity for instance in row.instances)
        band = K.band(value_usd)
        if value_usd is None or value_usd < 100_000:
            warnings.append(
                {
                    "kind": "value_at_stake_at_band_floor",
                    "unit": row.unit,
                    "capability": row.capability,
                    "note": (
                        "the weight sits at the band floor because the value this "
                        "capability is proven to reach is undetermined or below it. "
                        "This is not a claim that the entities hold nothing: position "
                        "and unpriced value are absent from the priced sheet, and this "
                        "is the one direction in which the model under-scores"
                    ),
                    "missing_witness": "priced value for the reached entities",
                }
            )
        rows.append(
            {
                "principal_unit": row.unit,
                "unit_members": sorted(units.published_units()["members"].get(row.unit, [row.unit])),
                # The published principal IS the one that set the weakness, not
                # whichever row was folded last.
                "principal": f"{weakest[0]} {weakest[2]}",
                "access_path": row.path,
                "principal_addresses": sorted(row.principal_addresses),
                "principal_kind": weakest[1],
                "capability": row.capability,
                "chain": row.unit.split("::", 1)[0],
                # The row's total and its per-entity breakdown are the SAME
                # floats the per-entity ceiling records publish — one derivation,
                # three keys, one finding object — so they take one rounding
                # (``_round_published``). Measured: five live upgrade.implementation
                # rows carry a sub-cent entity, and at cents the header said
                # "$0.00 at stake" and the breakdown said 0.0 while the record
                # beside them published the bound that was proven. The total is
                # included DELIBERATELY and not only the breakdown: on a row whose
                # one entity is that sheet, the header IS the row's claim, and
                # "$0.00 at stake" is the false-safety reading this whole change
                # exists to remove. It is immaterial today only because those five
                # sit inside a $4.2B row — a fact about this corpus, not a
                # property of the rule.
                #
                # Nothing GRADED moves with either key: ``value_band``,
                # ``value_at_stake_bound_direction`` and ``value_at_stake_is_floor``
                # are derived above from the UNROUNDED ``value_usd``, and the
                # weakness axis reads the unrounded ``per_entity``. But
                # ``value_by_entity`` is NOT inert — do not read this rounding as
                # a presentation-only key. ``_grade`` takes the exposure
                # numerator from it (``held = finding["value_by_entity"][key]``,
                # then ``mine += take * held`` into ``exposure_usd`` and so into
                # ``grade_exposure``), and the subsumed-exclusive selection
                # compares candidates on ``held * fraction`` and charges the
                # winner through the same loop.
                #
                # What keeps THIS change out of the numerator is §6.4, not an
                # absence of readers: a sheet ceiling is held out of exposure
                # entirely (``held = None`` there), and every sub-cent entity on
                # this corpus is a sheet ceiling. That is a rule with its own
                # lifetime and it may be revisited. Where a sub-cent entity is
                # NOT a sheet ceiling the charge can only GROW — the unrounded
                # figure is larger than the 0.00 it replaced — so exposure rises
                # and ``grade_exposure`` falls, and this rounding can never
                # manufacture an improvement.
                "value_at_stake_usd": (_round_published(value_usd) if value_usd is not None else None),
                "value_state": (VALUE_STATE_PROVEN_REACH if value_usd is not None else NOT_DETERMINED),
                "value_by_entity": {k: _round_published(v) for k, v in sorted(per_entity.items())},
                "value_at_stake_basis": value_basis,
                # Which direction the total bounds the principal in, and the
                # reason the flag below is no longer the whole answer: a sum of
                # composed extraction ceilings is not an at-least. Three-valued,
                # and ``not_determined`` is the fall-through — a direction is
                # published only where one was proven.
                "value_at_stake_bound_direction": direction,
                # Retained, and now derived: it is TRUE only where the direction
                # is a floor, so a consumer reading the boolean alone can no
                # longer read a ceiling as an at-least.
                "value_at_stake_is_floor": is_floor,
                # The entities whose published figure is a composed extraction
                # ceiling, named rather than left to be counted out of
                # reach_composed_magnitudes — that list holds every candidate,
                # including ones an entity's own witness beat. SPLIT from the
                # sheet ceilings below rather than widened to hold both: the two
                # are different claims about how the bound was earned, only one
                # of them spends the exposure budget, and a consumer joining
                # this list to reach_composed_magnitudes[] would find no entry
                # for a sheet entity that had been folded into it.
                "entities_priced_from_a_composed_ceiling": sorted(
                    valued.ceiling_entities - valued.sheet_ceiling_entities
                ),
                # The other ceiling: entities whose published figure is their OWN
                # priced sheet, admitted because this row's capability replaces
                # their code. Disjoint from the list above by construction — a
                # standing figure came from one branch — and the two together are
                # the row's ceiling-bearing population.
                "entities_priced_from_a_sheet_ceiling": sorted(valued.sheet_ceiling_entities),
                # Its refusal counterpart, and the reason it is published rather
                # than left to be counted out of the list above: on a row whose
                # every composed figure was withheld the ceiling list is EMPTY,
                # and an empty list there is otherwise the same shape as an
                # empty list on a row that never composed anything. One is a
                # typed refusal, the other is a question nobody asked, and
                # spelling them identically is the collapse three-valued logic
                # exists to prevent.
                "entities_withheld_from_a_composed_ceiling": [
                    {
                        "entity": record.entity,
                        "selector": record.selector,
                        "arm_taken": record.arm,
                        "withheld_reason": record.reason,
                        "authority_deletability_state": record.deletability.state,
                        "authority_deletability_reason": record.deletability.reason,
                    }
                    for record in valued.withheld_composed_magnitudes
                ],
                # The entities behind the coverage gap, named rather than left to
                # be inferred from the direction alone.
                "entities_holding_unpriced_assets": partially_priced,
                "value_band": (
                    (_BAND_PREFIX.get(direction, "") + K.band_label(value_usd))
                    if value_usd is not None
                    else NOT_DETERMINED
                ),
                "undetermined_instances": undetermined,
                "proven_no_reach_instances": valued.proven_no_reach,
                "witnessed_magnitude_caps": valued.magnitude_caps,
                # A floor witness the entity's own sheet could not bound. The
                # published dollars for these entities are the witness's figure
                # standing alone, which is a different fact from a figure two
                # witnesses agreed on.
                "unbounded_floor_magnitudes": valued.unbounded_floor_magnitudes,
                # Phase 6: every dollar this row carries that came from a
                # DESTINATION function's own flow.out witness rather than from a
                # witness on this row's own call, with the act-as chain that
                # licensed it published beside it (inv. 9 exact decomposition).
                "reach_composed_magnitudes": [
                    entry.as_json() for _, entry in sorted(valued.composed_magnitudes.items())
                ],
                # The other half of the same population: every candidate that
                # cleared all three composition witnesses and then lost its
                # FIGURE to the three-arm rule. Each one publishes its gate
                # claim, its execution record and its typed refusal, and no
                # dollar figure of any kind.
                "reach_composed_magnitudes_withheld": [
                    record.as_json() for record in valued.withheld_composed_magnitudes
                ],
                # The sheet ceilings this row publishes, one entry per entity,
                # each carrying the observation-shaped answer to #170's question:
                # a sheet ceiling is proven by a BALANCE OBSERVATION and not by a
                # call, so its proving_execution is not_determined under a
                # registered non-fault reason that says exactly that. Published
                # rather than left implicit, because a magnitude with no
                # execution block reads as one whose execution nobody asked about.
                "reach_sheet_ceiling_magnitudes": _sheet_ceiling_records(
                    valued.sheet_ceiling_entities, per_entity, value_plane, row.capability
                ),
                # Its refusal counterpart, published for the reason every refusal
                # on this row is: an entity silently absent from the list above
                # is indistinguishable from one the branch never fired on. These
                # are entities whose standing figure did not reconcile against
                # the sheet it claimed to be, so the ceiling LABEL was withheld —
                # the dollars stand, graded in no direction, and they charge the
                # exposure budget like any other figure.
                "reach_sheet_ceiling_magnitudes_withheld": valued.sheet_ceilings_withheld,
                "reach_composition_census": valued.composition_census,
                # ``witnessed_magnitude_caps`` lists only the calls a witness
                # actually TRIMMED. Read alone it says nothing about the calls
                # that carried no witness at all, which are the majority and
                # which a reader would otherwise take for "checked and within
                # bound". The census separates the three: capped, witnessed and
                # within its bound, and never witnessed.
                "magnitude_witness_census": {
                    **valued.magnitude_census,
                    "reading": (
                        "magnitude_not_witnessed is the population whose dollar figure is "
                        "not_determined and whose weight therefore sits at the unpriced band's "
                        "floor: no witness proved how much this reach moves, so nothing is "
                        "published as if one had. magnitude_composed is counted apart from both "
                        "— those calls carry no witness of their own and were priced on the "
                        "DESTINATION function's, itemised under reach_composed_magnitudes. "
                        "magnitude_sheet_ceiling is the third answer and is counted apart from "
                        "all of them: those calls carry no witness of their own either and were "
                        "priced from the CONTROLLED NODE's own sheet, which bounds them from "
                        "above rather than measuring them, itemised under "
                        "reach_sheet_ceiling_magnitudes. "
                        "within_witnessed_bound means a witness exists "
                        "and did not have to trim; it is not the same fact as no witness. "
                        "hops_not_determined counts every hop this row could not establish, of "
                        "which hops_not_determined_withholding_reach are the ones no other path "
                        "reached anyway — the rest bound nothing and are listed nowhere"
                    ),
                },
                # Hops the walk could establish neither way, deduped on the
                # distinct (caller, destination) pair. Reach withheld is still
                # reach this row does not claim — published so the bound is
                # visible instead of the closure quietly getting smaller.
                "reach_hops_not_determined": valued.hops_not_determined,
                "zero_address_reach_keys_refused": row.zero_reach_keys_refused,
                # Filled in after the sort, which is where a tie can be seen.
                # Present on every row: null is the proven "nothing tied".
                "exposure_order_tie": None,
                "severity_proven": round(severity, 4),
                "severity_basis": sorted({b for instance in row.instances for b in instance.severity_basis}),
                "weakness": round(weakness, 4),
                "weakest_gate": weakest[0],
                # inv.5 read as the weakest path TO AN ENTITY: present only where a
                # merged unit's members reach different entities at different rungs,
                # and then the union is priced at the hardest rung among the
                # contributing members. Absent means one rung priced the whole union.
                "weakness_by_entity": {k: round(v, 4) for k, v in sorted(weakness_by_entity.items())},
                "raw_points": round(K.SEV_SCALE * severity * weakness * band, 4),
                "n_functions": len({(i.signal.deployment_address, i.signal.selector) for i in row.instances}),
                "n_entities": len(row.seeds),
                # The deployment entities the row's instances were witnessed ON
                # — the direct targets — as distinct from reach_entities, the
                # closure the capability reaches through control edges. That
                # closure is MEMBERSHIP and is not filtered by pricing: the
                # entities in it whose dollars are undetermined are named in
                # the row's exposure gap, not dropped from the fact that this
                # capability reaches them.
                "host_entities": sorted(row.seeds),
                "reach_entities": sorted(valued.reach),
                # What the gate hops this row walked LICENSE at each destination
                # — the role -> selector join's named functions, keyed on the
                # canonical entity the reach set uses, as {selector, name}
                # objects rather than a string a consumer would have to re-parse.
                # A reached entity absent from this map was reached through a hop
                # that named no function, which is a reach whose "to do what" is
                # unanswered and not a reach to nothing.
                "reach_licensed_functions": valued.licensed_functions,
                # The size of what the withheld hops hide. Two published hops can
                # withhold twenty-two entities; without this the other twenty
                # appear nowhere in the document.
                "reach_withheld_behind_hops": valued.withheld_behind_hops,
                "example_functions": sorted({i.signal.function_name for i in row.instances})[:6],
                "witness_tiers": sorted(row.tiers),
                "witness_notes": sorted(row.notes),
                "citations": _cited(row.citations),
                # The slice above is a display cap, and a cap that is not counted
                # reads as the whole population. Two witness citations were
                # evicted by a reading-string on one shipped row before the
                # ordering below existed; the total says how many were not shown.
                "citations_total": len(row.citations),
                "counterfactual": _counterfactual(weakest[1]),
            }
        )

    by_unit: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_unit[row["principal_unit"]].append(row)
    findings: list[dict[str, Any]] = []
    subsumed: list[dict[str, Any]] = []
    for unit in sorted(by_unit):
        ordered = sorted(
            by_unit[unit], key=lambda r: (-r["raw_points"], r["capability"], r["access_path"], r["weakness"])
        )
        top = dict(ordered[0])
        rest = ordered[1:]
        top["subsumed_capabilities"] = [
            {
                "capability": r["capability"],
                "access_path": r["access_path"],
                "weakness": r["weakness"],
                "raw_points": r["raw_points"],
                "value_at_stake_usd": r["value_at_stake_usd"],
                "n_entities": r["n_entities"],
            }
            for r in rest
        ]
        top["subsumed_raw_points"] = round(sum(r["raw_points"] for r in rest), 4)
        # Subsumption removes a row's POINTS, never the unit's reach. Value that
        # only a subsumed row names is still value this unit provably reaches, and
        # dropping it from the exposure accounting would publish a smaller
        # exposure for a unit that got no smaller.
        #
        # The contributing row's OWN fraction travels with the value. The top row
        # is a different access path — often an undelayed one — and charging the
        # delayed row's value at the undelayed fraction would re-merge in the
        # exposure term exactly what keying rows by access path separated.
        #
        # A SHEET CEILING is not occupancy. The top row publishes a figure at
        # such an entity and charges nothing for it, so treating the key as
        # taken would discard a subsumed row's genuinely witnessed value there
        # and take it out of the exposure accounting altogether — a leak in the
        # direction the budget exists to prevent.
        occupied = set(top["value_by_entity"]) - set(top["entities_priced_from_a_sheet_ceiling"])
        exclusive: dict[str, dict[str, float]] = {}
        # Which exclusive keys arrived as a SUBSUMED row's sheet ceiling. The
        # skip in ``_grade`` reads the TOP row's ceilings, and value carried in
        # from a subsumed row is not on that list — so without this the ceiling
        # a subsumed row published would charge the budget the top row's own is
        # kept out of. Tracked per key beside the winning figure, because the
        # answer belongs to whichever row's figure actually won.
        exclusive_ceilings: set[str] = set()
        for row in rest:
            per_entity_weakness = row["weakness_by_entity"]
            row_ceilings = set(row["entities_priced_from_a_sheet_ceiling"])
            for key, held in row["value_by_entity"].items():
                if key in occupied:
                    continue
                fraction = row["severity_proven"] * per_entity_weakness.get(key, row["weakness"])
                previous = exclusive.get(key)
                if previous is None or held * fraction > previous["usd"] * previous["fraction"]:
                    exclusive[key] = {"usd": held, "fraction": round(fraction, 6)}
                    exclusive_ceilings.discard(key)
                    if key in row_ceilings:
                        exclusive_ceilings.add(key)
        top["subsumed_exclusive_value_by_entity"] = dict(sorted(exclusive.items()))
        # Published rather than left to be re-derived from the subsumed rows: the
        # exposure loop needs it, and a reader checking why an exclusive entity
        # was not charged has nowhere else to look.
        top["subsumed_exclusive_sheet_ceiling_entities"] = sorted(exclusive_ceilings)
        if rest:
            top["counterfactual"] += (
                "; this row subsumes " + ", ".join(r["capability"] for r in rest) + " — fixing the top "
                "capability alone does not release them"
            )
        findings.append(top)
        subsumed.extend(rest)
    findings.sort(key=lambda r: (-r["raw_points"], r["capability"], r["principal_unit"]))
    subsumed.sort(key=lambda r: (-r["raw_points"], r["capability"], r["principal_unit"]))
    _disclose_order_ties(findings)
    return findings, subsumed, warnings


def _order_tie_reading(shared_entities: list[str], position_in_tie: int) -> str:
    """What the tie-break string decided on THIS row, read off what the row holds.

    The λ half is true of every carrier — a tied row's index is that string's
    doing whatever else is true — so it is constant. Two things after it are
    not, and both are published in the same block a line away.

    ``shared_entities``: the order splits a budget only where an entity is
    actually held in common, and a row that shares none has no split. Publishing
    the split sentence there asserts an apportionment that provably did not
    happen, which is the same defect one level down from the figures.

    ``position_in_tie``: which SIDE of the split this row is on. The first row in
    a tie group has no tied row ahead of it and is charged FIRST; saying it "is
    charged the remainder" is false of exactly the carrier the field beside it
    identifies. The two directions are the same fact told from two ends, and
    naming the wrong end inverts who the order cost.
    """
    lam = "this row's λ position is decided by that string, not by evidence"
    if not shared_entities:
        return (
            lam + "; and it holds NO entity in common with the tied rows — shared_entities is "
            "an asked-and-empty, not an unasked question — so no exposure budget was split by the "
            "order here and none of this row's dollars is an order-determined apportionment"
        )
    shared_clause = (
        f"{lam}, and so is its share of the {len(shared_entities)} entity(ies) it holds in "
        "common with the tied rows (named under shared_entities): "
    )
    if position_in_tie == 0:
        charged = (
            "this row is FIRST in the tie (position_in_tie 0), so it consumes that shared exposure "
            "budget before any row tied with it and the rows behind it are charged the remainder"
        )
    else:
        charged = (
            f"the {position_in_tie} row(s) ahead of this one in the tie (position_in_tie "
            f"{position_in_tie}) consume that shared exposure budget first and this row is charged "
            "what is left of it"
        )
    return (
        shared_clause + charged + ", so the split among them is order-determined and is not a "
        "measurement of who reaches what"
    )


def _disclose_order_ties(findings: list[dict[str, Any]]) -> None:
    """Where rows tie on the sort key, say so: the order decides, and it is a string.

    Two rows with equal points and capability are separated by the unit address
    alone, and that order is spent twice — on the λ position, which discounts by
    index, and on the exposure budget, which the earlier row consumes first and
    the later row gets the remainder of. Splitting the shared entity correctly
    needs evidence this fold does not have, so the order stays fixed (inv. 8) and
    what it decided is published instead of read as an attribution.

    Findings only. A subsumed row has no λ position and spends no exposure
    budget — the order decides nothing for it — so its ``exposure_order_tie``
    stays ``None``, which here is the proven "nothing was decided by order",
    not an unasked question.
    """
    groups: dict[tuple[Any, Any], list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        groups[(finding["raw_points"], finding["capability"])].append(finding)
    for group in groups.values():
        if len(group) < 2:
            continue
        units = [f["principal_unit"] for f in group]
        for position, finding in enumerate(group):
            others = {key for other in group if other is not finding for key in other["value_by_entity"]}
            shared = sorted(set(finding["value_by_entity"]) & others)
            finding["exposure_order_tie"] = {
                "tied_with": [unit for unit in units if unit != finding["principal_unit"]],
                "shared_entities": shared,
                "position_in_tie": position,
                "basis": "equal raw_points and capability; the remaining order is the principal_unit string",
                "reading": _order_tie_reading(shared, position),
            }


# Every published dollar is rounded to the cent, so a share below half a cent
# reaches a consumer as $0.00 whatever it really was.
_PUBLISHED_CENT = 0.005

_UNPRICED_ASSET_STATES = frozenset({P.ASSET_UNPRICED, P.ASSET_BELOW_RESOLUTION})


def _asset_coverage(value_plane: P.ValuePlane, canonical: str) -> dict[str, Any]:
    """What one entity's priced sheet does and does not cover, per asset.

    The per-ASSET maps are read and the sheet STATE is not, for the reason
    :func:`_partially_priced_entities` reads them: the state collapses a mixed
    entity to whichever fact ranks highest, so an entity with one priced asset
    and a hundred unanswered ones reads as ``priced`` there and the shortfall
    disappears. ``below_resolution`` counts as not priced — an asset whose price
    landed on the storage floor is a holding of at most half a cent that the
    total does not carry, which is the same shortfall as one nobody priced — and
    the restaking plane is the second source, with no USD column at all.

    ``complete`` is the conjunct the ceiling claim turns on and it is an EARNED
    positive: an entity with no observed assets at all does not clear it by
    having nothing to fail on. Nothing here reads a block height or an observed
    account: the plane reduces observations to the latest per (entity, asset) at
    load, so those are gone by the time this runs and are not claimed.

    Two conjuncts of ``complete`` are about the LIST rather than the readings on
    it, and both are asked because a per-reading answer cannot reach them:

    * a list read AT the endpoint's page cap can never be complete. The stored
      rows are a prefix of the holdings, so every one of them being answered
      says nothing about the entries the page never reached.
    * a DISPOSED reading does not extend coverage over the list. A disposition
      says one asset's contribution is nil; it does not say the list is whole,
      and reading it as though it did is how a sheet assembled from a
      third-party page would come to publish a full-coverage upper bound. So a
      sheet carrying any disposed asset must have its list separately proven —
      by the chain's own transfer history — before it clears here.
    """
    values = value_plane.per_asset.get(canonical) or {}
    states = value_plane.per_asset_state.get(canonical) or {}
    positions = value_plane.unpriced_positions.get(canonical) or []
    names = sorted(set(values) | set(states))
    # A key present in ``per_asset`` with no state entry is read as determined,
    # which is what that map means (see ``ValuePlane``'s docstring).
    not_priced = sorted(name for name in names if states.get(name) in _UNPRICED_ASSET_STATES)
    disposed = sorted(name for name in names if states.get(name) == P.ASSET_AIRDROP_DELIVERED)
    list_is_whole = not value_plane.asset_set_is_truncated(canonical) and (
        not disposed or value_plane.asset_set_is_proven_complete(canonical)
    )
    return {
        "per_asset": [
            # The evidence a sheet-ceiling record's figure is checked against, so
            # it carries the same rounding the figure does: per-asset rows that
            # all read $0.00 under a published $0.00156 would contradict the sum
            # they are published to support.
            {
                "asset": name,
                "usd": (_round_published(values[name]) if name in values else None),
                "state": states.get(name),
            }
            for name in names
        ],
        "assets_observed": len(names),
        # Assets carrying a determined DOLLAR reading — a price, or a quantity
        # witnessed zero. The three populations partition ``assets_observed``:
        # a disposed asset carries no dollar figure at all (its ``usd`` is null
        # in ``per_asset``), so it is counted under ``assets_disposed`` and
        # under neither of the other two. Folding it in here published a sheet
        # whose every asset arrived by mass distribution as fully priced.
        "assets_priced": len(names) - len(not_priced) - len(disposed),
        "assets_not_priced": not_priced,
        "assets_disposed": disposed,
        # The LIST conjunct of ``complete``, published rather than left inside
        # it: a reader who sees the direction refused with both asset lists
        # empty has no other field to read the cause off, and an unpublished
        # conjunct is one the sentence beside it cannot name.
        "asset_list_proven_whole": list_is_whole,
        "unpriced_positions": len(positions),
        "complete": bool(names) and not not_priced and not positions and list_is_whole,
    }


def _reconcile_sheet_ceilings(
    ceiling_kinds: dict[str, str], per_entity: dict[str, float], value_plane: P.ValuePlane
) -> list[dict[str, Any]]:
    """Drop any sheet ceiling whose standing figure is not that node's sheet.

    S6's invariant is PER KEY: a sheet ceiling is capped by its own node's sheet
    by construction, because it IS that sheet, and the per-entity MAX only ever
    replaces it with something larger that is no longer a ceiling. It may not be
    checked on the row's total, which legitimately sums across priced hosts and
    exceeds any single sheet — $4.217B over eight of them on the reference
    corpus.

    Checked at the published resolution rather than exactly, because that is the
    resolution the claim is made at — and the check therefore goes through
    ``_round_published``, the function that DEFINES that resolution, rather than
    through a hand-written ``round(x, 2)`` that used to agree with it. The two
    stopped agreeing in the sub-cent band, where the published resolution is the
    unrounded figure: at cents a standing $0.004 and a sheet of $0.001 both read
    0.00, the gate passed, and a figure that is not this node's sheet was
    labelled its ceiling. The comparison is strictly tighter than the old one and
    admits nothing it did not admit before.

    Reconciled rather than raised: an
    unreachable-by-construction mismatch is still a claim this fold cannot
    support, and the honest response is to withhold the LABEL from that one key —
    the figure stands, ungraded for direction, and charges the exposure budget
    like any other — not to take a protocol's whole score down with it. Mutates
    ``ceiling_kinds`` in place and returns what it withheld, so the caller
    publishes the refusal rather than a silence.
    """
    withheld: list[dict[str, Any]] = []
    for entity in sorted(ceiling_kinds):
        if ceiling_kinds[entity] != CEILING_KIND_SHEET:
            continue
        usd, reason = P.ceiling_for(value_plane, entity)
        if usd is not None and _round_published(per_entity[entity]) == _round_published(usd):
            continue
        del ceiling_kinds[entity]
        withheld.append(
            {
                "entity": entity,
                # The two figures the gate above just found unequal, published at
                # the resolution it compared them at. At cents a pair that
                # differs only below one would print here as two identical
                # numbers under a record whose whole claim is that they differ.
                "standing_usd": _round_published(per_entity[entity]),
                "sheet_usd": (_round_published(usd) if usd is not None else None),
                "ceiling_reason": reason,
                "why": "standing_figure_is_not_this_nodes_sheet(ceiling_label_withheld)",
                "reading": (
                    "the figure standing at this entity is not the one its own sheet answers, so "
                    "it is not a sheet ceiling and is not labelled one. The dollars are published "
                    "unchanged and graded in no direction, and they charge the exposure budget: "
                    "the exemption belongs to a proven upper bound and this figure has not been "
                    "shown to be one"
                ),
            }
        )
    return withheld


def _partially_priced_entities(value_plane: P.ValuePlane, keys: set[str]) -> list[str]:
    """Reached entities whose priced sheet does not cover everything they hold.

    Whole-entity unpricedness already lands in ``undetermined_instances``; this
    is the case one level in, where the entity IS priced but only partly — ten
    priced rows beside a hundred unpriced ones answer ten questions, and a total
    over them is a floor, not the entity's value.

    Two sources, ORed, and the per-ASSET map is read rather than the sheet
    state: the sheet state collapses a mixed entity to whichever fact ranks
    highest, so an entity with one priced asset and a hundred unanswered ones
    reads as ``priced`` there and the shortfall disappears. ``below_resolution``
    counts as unpriced here — an asset whose price landed on the storage floor
    is a holding of at most half a cent that the total does not carry, which is
    the same shortfall as one nobody priced. The restaking plane is the second
    source: it has no USD column at all, so a position there is unpriced by
    construction.
    """
    partial: set[str] = set()
    for key in keys:
        canonical = value_plane.canonical(key)
        if value_plane.total(canonical) is None:
            # Nothing determined at all: an undetermined entity, not a floor.
            continue
        # The same predicate the per-entity sheet-ceiling record publishes its
        # bound direction from, called rather than restated: the row header and
        # the per-entity record answer the same coverage question, and two
        # copies of the rule are how they came to answer it differently.
        if not _asset_coverage(value_plane, canonical)["complete"]:
            partial.add(canonical)
    return sorted(partial)


def _bound_direction(
    value_usd: float | None,
    entities: frozenset[str],
    ceiling_entities: frozenset[str],
    coverage_gap: bool,
    withheld_reach: bool,
    non_attributed_entities: frozenset[str],
) -> str:
    """Which direction the row's published total bounds this principal in.

    Two independent axes, and the header used to publish only one of them. The
    COVERAGE axis is what ``is_floor`` was designed for: instances that answered
    nothing and entities holding assets the priced sheet never covered leave
    value out of the sum, so what is in it is a floor. The BOUND axis is the
    other one: a composed figure is the DESTINATION function's witness for one
    call, and it is a ceiling on what this principal extracts because the
    witness bounds the FUNCTION whoever calls it and carries no model of who
    calls it.

    Summing ceilings does not make a floor, so ``floor`` requires that NO
    contributing entity's figure came through the composed branch — the
    invariant that keeps a genuinely witnessed floor exactly where it was.

    The composed branch is not the only ceiling in the building, which is the
    F5 correction. An ATTRIBUTION-DERIVED contribution — a holder's whole priced
    balance credited off a constant-amount probe — bounds this principal from
    above too, and it arrives through the instance's OWN witness, where the
    ceiling test above never looks. So ``floor`` additionally requires that
    every contributing entity's standing figure be PROVEN not attribution-derived.

    That conjunct is written as a membership test and not as "no contribution is
    attributed", deliberately. A universal over contributions is VACUOUSLY TRUE
    on a row with no contributions at all, and a row that lost every figure would
    then earn a floor over an empty sum — today that is unreachable only because
    :func:`_row_value` returns early with ``value_usd = None`` when ``per_entity``
    empties, i.e. because of a guard in a different function. An earned positive
    does not depend on a guard somewhere else: ``entities`` must be non-empty and
    every one of its members must be in the proven-not-attributed set.

    ``ceiling`` is the mirror and is earned no more cheaply: EVERY contributing
    entity's figure must be a proven ceiling (one ungraded contribution and the
    sum is not bounded above by these), nothing may be missing from the sum (a
    coverage gap or a withheld hop is value this row reaches that the total does
    not carry, and either one breaks an at-most while leaving an at-least
    intact), and the two are checked here rather than asserted in the prose.

    ``ceiling_entities`` carries TWO populations and this function reads neither
    apart: a composed extraction ceiling and a controlled node's own sheet
    ceiling are proven differently and narrowed differently, and both bound this
    principal from above, which is the whole of what direction asks. The
    per-entity records say which is which, and the coverage conjunct above is
    what stops a partly priced sheet from being summed into an at-most — the
    same conjunct the per-entity record derives its own direction from.

    Everything else is ``not_determined``, including a total with no gap and no
    ceiling in it: the contributions are then a mix this fold does not grade for
    direction — a priced floor bounded by a sheet is not an exact figure — and
    the absence of the two signals above is not a witness that the sum is
    two-sided. It publishes the bare band and claims nothing.
    """
    if value_usd is None:
        return BOUND_DIRECTION_NOT_DETERMINED
    if ceiling_entities:
        if ceiling_entities == entities and not coverage_gap and not withheld_reach:
            return BOUND_DIRECTION_CEILING
        return BOUND_DIRECTION_NOT_DETERMINED
    if not coverage_gap:
        return BOUND_DIRECTION_NOT_DETERMINED
    if entities and entities <= non_attributed_entities:
        return BOUND_DIRECTION_FLOOR
    return BOUND_DIRECTION_NOT_DETERMINED


# One clause per ceiling KIND, each naming the population it counted and the
# per-entry block a reader can check it against. Assembled per row rather than
# written once, because a row can carry either ceiling or both and a sentence
# naming only one of them is false about the figures it does not mention.
_CEILING_KIND_CLAUSES = {
    CEILING_KIND_COMPOSED: (
        "priced from a composed extraction CEILING — the DESTINATION function's own flow.out "
        "witness, which bounds one call to that function whoever makes it (see "
        "reach_composed_magnitudes[])"
    ),
    CEILING_KIND_SHEET: (
        "priced from a SHEET CEILING — the controlled node's own priced holdings, which bound "
        "from above what replacing that node's code can move at it (see "
        "reach_sheet_ceiling_magnitudes[])"
    ),
}

# What each kind of ceiling bounds, for the arm that earned a direction. The
# composed sentence is about one CALL; the sheet sentence is about one NODE, and
# each is false of the other kind.
_CEILING_KIND_BOUNDS = {
    CEILING_KIND_COMPOSED: "Each composed figure bounds ONE call to the destination function",
    CEILING_KIND_SHEET: (
        "Each sheet figure bounds what replacing ONE node's code can move AT THAT NODE, and "
        "nothing about what that node in turn governs"
    ),
}


def _asset_set_completeness(value_plane: P.ValuePlane, entity: str) -> dict[str, Any] | None:
    """The carrier record proving this entity's asset list whole, or ``None``.

    Copied out of the plane rather than rebuilt: the strings inside are the
    producer's own ``asset_set_basis`` values, so what the document publishes
    about a scan is the scan's own record and not a sentence authored at the
    point of publication.
    """
    record = value_plane.asset_set_proven_complete.get(value_plane.canonical(entity))
    return dict(record) if record is not None else None


def _disposition_carrier(value_plane: P.ValuePlane, entity: str, disposed: list[str]) -> dict[str, Any] | None:
    """The delivery evidence this entity's disposed readings actually stand on.

    Read off ``ValuePlane.asset_disposition`` — the records the plane copied from
    the producer's own rows — and never re-derived here. ``None`` where nothing
    at this entity is disposed, which is the third state: a row with no disposed
    reading has no delivery evidence to publish, and an empty block would read
    as evidence that came back empty.

    The aggregate takes the WEAKEST end of each field across the readings it
    folds, for the same reason the plane takes it across accounts: the sentence
    published beside it is one claim over the whole set, and it holds only where
    every member holds. So the smallest fan-out any reading measured, the latest
    block any scan started from, and the earliest block any of them ran through.
    """
    carriers = [
        record
        for asset in disposed
        if (record := (value_plane.asset_disposition.get(value_plane.canonical(entity)) or {}).get(asset)) is not None
    ]
    if not carriers:
        return None
    fan_outs = [record["min_fan_out"] for record in carriers if record["min_fan_out"] is not None]
    return {
        "assets": len(carriers),
        "shapes": sorted({record["shape"] for record in carriers}),
        "fan_out_threshold_k": max(record["fan_out_threshold_k"] for record in carriers),
        # ``null`` is the honest answer where no reading recorded a fan-out, and
        # is never read as zero: a delivery nobody measured is not a delivery
        # that reached nobody.
        "min_fan_out": (min(fan_outs) if fan_outs else None),
        "delivery_count": sum(record["delivery_count"] for record in carriers),
        "scanned_from_block": max(record["scanned_from_block"] for record in carriers),
        "measured_through_block": min(record["measured_through_block"] for record in carriers),
        "accounts": sorted({account for record in carriers for account in record["accounts"]}),
        # The producers' own basis strings, deduplicated and otherwise verbatim.
        "basis": sorted({line for record in carriers for line in record["basis"]}),
    }


def _disposition_scope(coverage: dict[str, Any], carrier: dict[str, Any]) -> str:
    """What this entity's figure covers, and what it deliberately does not.

    Derived from the row's own counts and the carrier's own fields (#171), so
    the scope a reader checks is the scope the evidence supports rather than a
    sentence authored beside it. It is written for the figure and not for one of
    its values: on a sheet whose every reading is disposed the total is $0 and
    the count it totals over is ZERO, which is the honest way to publish that
    figure — the difference between "this sheet prices nothing" and "this entity
    holds nothing", of which only the first is witnessed here.
    """
    fan_out = carrier["min_fan_out"]
    return (
        f". The figure is SCOPED, and the scope is this row's own counts: it totals the "
        f"{coverage['assets_priced']} asset(s) here that carry a determined dollar reading, and "
        f"the {len(coverage['assets_disposed'])} asset(s) under assets_disposed are STILL HELD at "
        f"{len(carrier['accounts'])} account(s) and carry no valuation anywhere in this document. "
        f"What was measured of those is how they ARRIVED — {carrier['delivery_count']} recorded "
        f"delivery(ies), the smallest of them carrying "
        f"{fan_out if fan_out is not None else NOT_DETERMINED} same-token transfer log(s) in one "
        f"transaction against a published threshold of {carrier['fan_out_threshold_k']}, read over "
        f"blocks {carrier['scanned_from_block']}-{carrier['measured_through_block']} (see "
        "asset_disposition) — and never what they are worth, which is not_determined here. So "
        "this figure is a total over what the document PRICES at this node, and nothing on the "
        "entry says the held assets are worth nothing or that the entity holds nothing"
    )


def _sheet_ceiling_records(
    sheet_ceilings: frozenset[str],
    per_entity: dict[str, float],
    value_plane: P.ValuePlane,
    capability: str,
) -> list[dict[str, Any]]:
    """One published record per entity whose figure is its own sheet.

    Assembled off the row's STANDING figures rather than at the moment the branch
    fired, for the same reason the ceiling set is: a row folds several calls and
    only the figure that survived the per-entity MAX is the one published, so a
    record written per call would name entities the row does not price this way.

    Each record answers #170 in the only shape that is true here. Every published
    magnitude carries the execution that proved it; this one was not proven by a
    call at all, so it carries the registered NON-FAULT reason saying so. That
    the reason is outside :data:`EX.FAULT_REASONS` is load-bearing rather than
    incidental: the structural census walks every ``proving_execution`` key in
    the document and a fault reason here would qualify the whole grade as
    fault-degraded on the strength of a proof that is intact. The observations
    the record stands on are PUBLISHED here — the per-asset figures at the
    canonical key — because a record whose reading names evidence the document
    does not carry is the authored-string defect one level up from the one the
    execution block exists to close.

    ``bound_direction`` is DERIVED from this entity's own asset coverage and is
    not the constant the branch's name suggests. A priced sheet is a floor over
    what was priced, so on an entity holding assets nobody priced the figure
    bounds the priced portion and not the move — publishing ``ceiling`` there
    would claim an at-most over holdings this fold never observed, and would
    contradict the row header, which refuses a ceiling on exactly this conjunct.

    ``sheet_state`` and ``ceiling_reason`` are read back off the plane instead of
    carried down from the branch, so the record cannot claim a state the plane
    would not answer for the same key at the same moment.
    """
    records: list[dict[str, Any]] = []
    for entity in sorted(sheet_ceilings):
        usd, reason = P.ceiling_for(value_plane, entity)
        coverage = _asset_coverage(value_plane, entity)
        complete = coverage.pop("complete")
        carrier = _disposition_carrier(value_plane, entity, coverage["assets_disposed"])
        records.append(
            {
                "entity": entity,
                "capability": capability,
                # Both figures, and the per-asset evidence below them, take the
                # SAME rounding — see ``_round_published``. The two keys are equal
                # by construction and the ``per_asset`` block is what the sum is
                # checked against, so a convention that rounded one of them onto
                # zero would publish a record contradicting itself at exactly the
                # sub-cent sheets this rounding was hiding.
                "published_usd": _round_published(per_entity[entity]),
                # What the plane answers now, beside the figure the fold took.
                # Equal by construction and RECONCILED before this runs, so an
                # entry reaching here has been checked rather than asserted —
                # and checked through the SAME ``_round_published`` these two
                # keys are printed with, so the equality a reader sees is the
                # equality the gate tested. They drifted once and the gap was
                # exactly the sub-cent band.
                "sheet_usd": (_round_published(usd) if usd is not None else None),
                "sheet_state": value_plane.sheet_state(entity),
                "ceiling_reason": reason,
                "bound_direction": (BOUND_DIRECTION_CEILING if complete else BOUND_DIRECTION_NOT_DETERMINED),
                "bound_direction_basis": _sheet_ceiling_direction_basis(coverage, complete),
                # What proves the asset list this figure is summed over is the
                # WHOLE list, carried from the observation record rather than
                # restated here: the source token, the block range the chain's
                # own transfer history was read across, and the producer's own
                # basis strings. ``null`` is the third state — no scan on record
                # — which is every ADMITTED entry on this corpus and is why they
                # bound the priced portion and not the move.
                "asset_set_completeness": _asset_set_completeness(value_plane, entity),
                # The delivery evidence a disposed reading stands on, carried
                # from the plane's own records rather than restated: the
                # sentence below quotes these fields, so a reader checks the
                # claim against the evidence and not against the prose.
                # ``null`` where no reading here is disposed.
                "asset_disposition": carrier,
                **coverage,
                PROVING_EXECUTION_KEY: EX.not_determined(EX.REASON_NOT_PROVEN_BY_A_CALL).as_json(),
                "reading": (
                    _CEILING_SOURCE_READINGS[(reason, complete)]
                    # The shortfall, from the SAME derivation the direction
                    # basis publishes it from. The stems above may not name a
                    # cause: on a live carrier two of the three read empty, so a
                    # stem that presupposed one pointed a reader at fields that
                    # said nothing while the conjunct that failed went unnamed.
                    + (_CEILING_COVERAGE_SHORTFALL_PREFIX + _coverage_shortfall(coverage) if not complete else "")
                    + (_disposition_scope(coverage, carrier) if carrier is not None else "")
                    + _CEILING_CLOSING
                ),
            }
        )
    return records


def _ceilings_present(
    composed_ceilings: frozenset[str], sheet_ceilings: frozenset[str]
) -> list[tuple[str, frozenset[str]]]:
    """The ceiling kinds this row actually carries, in a fixed order.

    An empty kind writes no clause anywhere. A row carrying one kind therefore
    reads exactly as it did before the other existed — which is what keeps a row
    that did not move from having its prose move.
    """
    present = ((CEILING_KIND_COMPOSED, composed_ceilings), (CEILING_KIND_SHEET, sheet_ceilings))
    return [(kind, entities) for kind, entities in present if entities]


def _ceiling_source_phrase(
    composed_ceilings: frozenset[str], sheet_ceilings: frozenset[str], *, all_of_them: bool
) -> str:
    """Which ceiling(s) the row's figures came from, counted per kind.

    ``all_of_them`` is the arm where every contributing entity is a ceiling, and
    it is passed rather than inferred from the sets: the caller has already
    established it against the coverage axes, and re-deriving it here off a
    length comparison would restate a conclusion this function cannot check.
    """
    parts = _ceilings_present(composed_ceilings, sheet_ceilings)
    if len(parts) == 1:
        return ("every one of them " if all_of_them else "") + _CEILING_KIND_CLAUSES[parts[0][0]]
    counts = "; ".join(f"{len(entities)} {_CEILING_KIND_CLAUSES[kind]}" for kind, entities in parts)
    return ("every one of them a proven ceiling — " if all_of_them else "of which ") + counts


def _ceiling_bound_phrase(composed_ceilings: frozenset[str], sheet_ceilings: frozenset[str]) -> str:
    """What each kind of ceiling on this row bounds, one sentence per kind."""
    return "; ".join(_CEILING_KIND_BOUNDS[kind] for kind, _ in _ceilings_present(composed_ceilings, sheet_ceilings))


def _ceiling_untightened(
    composed_ceilings: frozenset[str],
    sheet_ceilings: frozenset[str],
    composed: dict[str, _ComposedMagnitude],
) -> str:
    """What, in THIS document, could put the true figure below each ceiling.

    Two different answers, so two clauses. For a COMPOSED ceiling it is the
    destination function's own stored conditions, counted off the row's own
    entries rather than named from a field that no longer exists. For a SHEET
    ceiling it is which of the node's assets replaced code can actually reach —
    a question nothing here asks, and the reason the figure is typed as a bound
    and not as an amount.
    """
    parts: list[str] = []
    if composed_ceilings:
        with_conditions = sum(
            1 for entity in composed_ceilings if entity in composed and composed[entity].predicates.descriptions
        )
        if with_conditions:
            parts.append(
                f"the destination function's own stored conditions travel with {with_conditions} of "
                f"those {len(composed_ceilings)} figure(s) (destination_predicates) and this fold "
                "evaluates none of them"
            )
        else:
            parts.append(
                f"no condition text was extracted for any of those {len(composed_ceilings)} figure(s) "
                "(destination_predicates), so the destination's own conditions are not available "
                "here to check the ceiling against at all"
            )
    if sheet_ceilings:
        parts.append(
            f"each of the {len(sheet_ceilings)} sheet figure(s) is that node's WHOLE priced sheet, and "
            "nothing here witnesses that replaced code reaches every asset on it — an accounting "
            "entry, or a balance another contract holds, is inside the sheet and outside the move"
        )
    return "and nothing here tightens it: " + "; ".join(parts)


def _disposed_ceiling_clause(value_plane: P.ValuePlane, sheet_ceilings: frozenset[str]) -> str:
    """The row-header's scoping clause for a sheet ceiling determined at $0.

    Empty on every row that carries none, so a row nothing moved on keeps its
    prose. Where one does, the header may not leave the reader with "$0 at a
    node this principal controls" and nothing else: the assets that sheet holds
    are still held, and what was proven of them is the shape they arrived in.
    Counted off the plane's own disposition records, never re-derived.
    """
    scoped = [
        entity
        for entity in sorted(sheet_ceilings)
        if P.ceiling_for(value_plane, entity)[1] == P.CEILING_AIRDROP_DETERMINED
    ]
    if not scoped:
        return ""
    assets = sum(len(value_plane.asset_disposition.get(value_plane.canonical(entity)) or {}) for entity in scoped)
    return (
        f"; {len(scoped)} of those sheet figure(s) is a DETERMINED ZERO of a scoped kind — "
        f"{assets} asset(s) at those node(s) are STILL HELD and this document values none of "
        "them, so the zero totals what it prices there and is never a claim that the holdings "
        "are worth nothing (reach_sheet_ceiling_magnitudes[].asset_disposition carries the "
        "delivery evidence, and their worth is not_determined)"
    )


def _ceiling_bearing_basis(
    direction: str,
    per_entity: dict[str, float],
    composed_ceilings: frozenset[str],
    sheet_ceilings: frozenset[str],
    undetermined: list[dict[str, Any]],
    partially_priced: list[str],
    proven_no_reach: list[dict[str, Any]],
    zero_reach_stripped: list[dict[str, Any]],
    hops_not_determined: list[dict[str, Any]],
    withheld_behind_hops: dict[str, Any],
    composed: dict[str, _ComposedMagnitude],
    value_plane: P.ValuePlane,
) -> str:
    """The basis for a row some of whose figures bound the principal from above.

    Written here rather than in :func:`_row_value` because the coverage half of
    the question is only complete once the zero-reach instances and the partly
    priced entities are known. The floor basis is left untouched: a row whose
    direction did not move must not have its prose move either.

    TWO ceiling kinds reach this writer and they are counted apart, never summed
    into one "ceiling" population. A composed extraction ceiling is a
    destination function's witness for one CALL and what could narrow it is that
    function's own stored conditions; a sheet ceiling is one NODE's whole priced
    holdings and what could narrow it is which of those assets replaced code can
    actually reach. One sentence over both would be a claim about the row that is
    false of whichever half it was not written for.

    Every clause names the population it counted. The ceiling arm in particular
    may not say "nothing is missing" as an unchecked flourish — the hops this
    row could not establish and the graph withheld behind them are value the sum
    does not carry, and they are named here because they were consulted in
    :func:`_bound_direction` before the arm was taken.

    ``composed`` is read for one clause only, and it is read rather than
    asserted: a ceiling can overstate what this principal actually extracts, and
    the only evidence in this document that could narrow a COMPOSED one is the
    destination function's OWN stored conditions, which travel with each composed
    entry and which this fold evaluates none of. How many of the row's
    ceiling-bearing figures carry that text is a fact about the row and is
    counted here. It replaces a clause naming an extraction precondition this
    document no longer publishes — a definite reference to a deleted field, which
    reads as a constraint that was consulted.
    """
    ceiling_entities = composed_ceilings | sheet_ceilings
    n_entities = len(per_entity)
    counted = f"{len(ceiling_entities)} of {n_entities} entity(ies)"
    scoped = _disposed_ceiling_clause(value_plane, sheet_ceilings)
    if direction == BOUND_DIRECTION_CEILING:
        return (
            (
                f"<= the sum over {n_entities} entity(ies), "
                + _ceiling_source_phrase(composed_ceilings, sheet_ceilings, all_of_them=True)
                + "; no instance is not_determined, no entity holds assets the priced sheet does not "
                "cover, and no hop of this row was left undetermined or withheld behind one — so "
                "nothing this row reaches is missing from the sum and the total bounds this "
                "principal from ABOVE. " + _ceiling_bound_phrase(composed_ceilings, sheet_ceilings)
            )
            + (f"; {len(proven_no_reach)} instance(s) proven_no_reach" if proven_no_reach else "")
            + scoped
        )

    # Why it is not a ceiling either, counted rather than asserted: value this
    # row reaches that the sum does not carry, plus contributions that are not
    # ceilings and that this fold does not grade for direction at all.
    missing: list[str] = []
    if undetermined:
        clause = f"{len(undetermined)} instance(s) not_determined"
        if zero_reach_stripped:
            clause += f" (of which {len(zero_reach_stripped)} reached only the refused zero address)"
        missing.append(clause)
    if partially_priced:
        missing.append(f"{len(partially_priced)} entity(ies) holding assets the priced sheet does not cover")
    if hops_not_determined:
        missing.append(f"{len(hops_not_determined)} hop(s) not_determined withholding reach")
    behind = withheld_behind_hops.get("entities") or 0
    if behind:
        missing.append(f"{behind} entity(ies) withheld behind those hops (see reach_withheld_behind_hops)")
    ungraded = n_entities - len(ceiling_entities)
    if ungraded:
        missing.append(f"{ungraded} entity(ies) whose figure is not a proven ceiling and is graded in no direction")
    untightened = _ceiling_untightened(composed_ceilings, sheet_ceilings, composed)
    basis = (
        f"bounded in NEITHER direction: {counted} "
        + _ceiling_source_phrase(composed_ceilings, sheet_ceilings, all_of_them=False)
        + " — a ceiling does not become a floor "
        f"by being summed, {untightened}; " + ", ".join(missing) + " leave the sum short of a ceiling on the row too"
    )
    if proven_no_reach:
        basis += f"; {len(proven_no_reach)} instance(s) proven_no_reach"
    return basis + scoped


def _coverage_bearing_basis(
    direction: str,
    per_entity: dict[str, float],
    undetermined: list[dict[str, Any]],
    partially_priced: list[str],
    non_attributed_entities: frozenset[str],
    proven_no_reach: list[dict[str, Any]],
    zero_reach_stripped: list[dict[str, Any]],
) -> str:
    """The basis for a row with a coverage gap and no ceiling-bearing figure.

    The gap is what a floor is made of — value this row reaches that the sum
    does not carry can only push the truth up — but it is not the whole of it.
    :func:`_bound_direction` also requires every contributing entity's standing
    figure to be PROVEN free of an upper-bounding witness, and where that second
    axis refuses, the row bounds this principal in neither direction. The two
    arms are written together here so the prose and the header can never come
    apart: the floor sentence is reachable only from the branch that earned the
    floor.

    Both arms count the SAME two populations. The gap the floor is earned from
    is instances that answered nothing AND entities holding assets the priced
    sheet never covered — the coverage axis reads both, and the floor string
    used to name only the first, which read as a floor over a fully priced
    entity set on a row where one entity was partly priced.
    """
    n_entities = len(per_entity)
    missing: list[str] = []
    if undetermined:
        clause = f"{len(undetermined)} instance(s) not_determined"
        if zero_reach_stripped:
            clause += f" (of which {len(zero_reach_stripped)} reached only the refused zero address)"
        missing.append(clause)
    if partially_priced:
        missing.append(f"{len(partially_priced)} entity(ies) holding assets the priced sheet does not cover")
    if direction == BOUND_DIRECTION_FLOOR:
        basis = f">= proven floor over {n_entities} entity(ies); " + ", ".join(missing)
    else:
        # Counted off the membership test the direction was refused on, and
        # named as what that test establishes: NOT proven free of an
        # upper-bounding witness. The attribution path is the live producer of
        # this refusal and is glossed, but a sheet ceiling whose label was
        # withheld lands here too, so the population may not be asserted to be
        # attribution-derived — only that none of it is proven not to be.
        ungraded = len(set(per_entity) - non_attributed_entities)
        basis = (
            f"bounded in NEITHER direction: {ungraded} of {n_entities} entity(ies) contribute a figure "
            "NOT proven free of an upper-bounding witness — the attribution path credits a holder's "
            "whole priced balance off a constant-amount probe, which bounds this principal from ABOVE "
            "— so the sum is not an at-least; " + ", ".join(missing) + " leave it short of an at-most too"
        )
    if proven_no_reach:
        basis += f"; {len(proven_no_reach)} instance(s) proven_no_reach"
    return basis


def _row_value(
    row: _Row,
    value_plane: P.ValuePlane,
    closure: P.ControlClosure,
    conditions: P.ConditionPlane,
    conferral: P.ConferralPlane,
    act_as: P.ActAsPlane,
    magnitudes: dict[tuple[str, str], _DestinationMagnitude],
    admission: _AdmissionPlanes,
) -> _RowValue:
    """Value at stake for one row: MAX per entity, never SUM.

    Two functions reaching the same vault charge it once, and the only dollar
    figure this function will publish against an entity is one a magnitude
    WITNESS proved — the entity's whole balance sheet answers "what is there",
    never "what this reach can move". The magnitude is also one number for the
    whole CALL, so it caps that call's sum across the keys it reached rather than
    being re-charged at each of them.

    The reach itself is bounded by the capability's class: code control expands
    over the whole closure of the controlled node, gate control only through
    edges whose scope the gate confers, and both only where the destination's
    own conditions do not pin their caller to the destination itself.

    Where a gate's own call carries no magnitude witness, the DESTINATION
    function's may supply one (:func:`_compose`, Phase 6). That is a reuse of an
    existing witness and never a second source of dollars: it applies only where
    the instance proved no magnitude itself, and each composed figure is capped
    at the destination's own witness and at the destination's own sheet.

    The conferral question is asked with the WITNESSED FUNCTION's own grant, per
    instance: two ownership.transfer functions that rewrite different variables
    confer different hops, and asking the capability class would walk one row's
    reach on another row's witness.
    """
    per_entity: dict[str, float] = {}
    # The entities whose standing figure in ``per_entity`` bounds this principal
    # from above, each mapped to WHICH ceiling it is — a composed extraction
    # ceiling or the controlled node's own sheet. Maintained beside the MAX
    # rather than after it: which branch produced a figure is only knowable where
    # the figure is chosen.
    ceiling_kinds: dict[str, str] = {}
    # Maintained beside the MAX for the same reason ``ceiling_entities`` is: the
    # witness behind a figure is only knowable where that figure is chosen.
    non_attributed_entities: set[str] = set()
    reached: set[str] = set()
    undetermined: list[dict[str, Any]] = []
    proven_no_reach: list[dict[str, Any]] = []
    magnitude_caps: list[dict[str, Any]] = []
    unbounded_floors: list[dict[str, Any]] = []
    # Every candidate every instance offered per entity, kept rather than
    # collapsed on arrival: the merge below has to choose between candidates
    # that tie on dollars, and a running MAX destroys the losers before the tie
    # can be seen, let alone published.
    composition_candidates: dict[str, list[_ComposedMagnitude]] = {}
    composition_census: dict[str, int] = {}
    composition_refusals: dict[str, int] = defaultdict(int)
    # Every composed candidate whose FIGURE the three-arm rule refused, keyed on
    # the call it refused so two instances reaching it report one refusal.
    withheld_composed: dict[tuple[str, str], _WithheldComposition] = {}
    composed_signals: set[tuple[Any, ...]] = set()
    # The signals whose sheet ceiling is the STANDING figure at each entity,
    # kept per entity so a figure the MAX later replaces takes its credit with
    # it. Built on ``composed_signals``' pattern and kept apart from it: a
    # ceiling and a composed destination witness answer the same question with
    # different evidence, and a consumer crediting either has to be able to say
    # which.
    ceiling_signals_by_entity: dict[str, set[tuple[Any, ...]]] = {}
    hops: dict[tuple[str, str], dict[str, Any]] = {}
    licensed: dict[str, set[P.LicensedFunction]] = defaultdict(set)
    census: dict[str, Any] = dict.fromkeys(
        (
            "instances",
            "magnitude_witnessed",
            "magnitude_composed",
            "magnitude_sheet_ceiling",
            "magnitude_not_witnessed",
            "capped",
            "within_witnessed_bound",
        ),
        0,
    )
    code_control = row.capability in K.CODE_CONTROL_CAPABILITIES
    transitive = code_control or row.capability in K.GATE_CONTROL_CAPABILITIES

    for instance in sorted(row.instances, key=lambda i: (i.signal.deployment_address, i.signal.function_name)):
        entity = entity_key(instance.signal.chain, instance.signal.deployment_address)
        if instance.pricing_blocked:
            undetermined.append(
                {"function": instance.signal.function_name, "entity": entity, "why": instance.pricing_blocked}
            )
            continue
        if instance.asset_identity_undecidable and not instance.magnitude.is_determined:
            undetermined.append(
                {
                    "function": instance.signal.function_name,
                    "entity": entity,
                    "why": "token_identity_not_decidable(unpriced branch)",
                }
            )
            continue
        if instance.signal.value_state == VALUE_STATE_PROVEN_NO_REACH:
            # An EARNED negative, not a gap: reach was witnessed and reached
            # nothing. Counting it among the undetermined instances would make a
            # proven fact read as a missing one.
            proven_no_reach.append(
                {"function": instance.signal.function_name, "entity": entity, "basis": instance.signal.value_basis}
            )
            continue
        if instance.signal.value_state != VALUE_STATE_PROVEN_REACH:
            # The transitive closure is a REACH, not a licence: a signal whose own
            # reach was never witnessed contributes no seed, however much value
            # its deployment's neighbours hold.
            undetermined.append(
                {"function": instance.signal.function_name, "entity": entity, "why": instance.signal.value_basis}
            )
            continue

        keys = set(instance.entity_keys)
        composed: dict[str, _ComposedMagnitude] = {}
        if transitive:
            grant = (
                None
                if code_control
                else conferral.grant_for(
                    instance.signal.claim_id,
                    instance.signal.function_id,
                    entity=entity,
                    selector=instance.signal.selector,
                )
            )
            seeds = set(keys)
            keys, withheld, licensed_here, walked_hops = _closure(keys, closure, conditions, grant=grant)
            for hop in withheld:
                hops.setdefault((hop["caller"], hop["destination"]), hop)
            # Keyed on the CANONICAL entity, the same key ``reached`` uses. The
            # walk speaks in raw edge anchors and an implementation folded onto
            # its proxy is one entity under two of them, so a consumer joining
            # the licensed functions to the reach set would silently miss every
            # destination that folds.
            for destination, functions in licensed_here.items():
                licensed[value_plane.canonical(destination)].update(functions)
            if not code_control:
                # Phase 6. Code control asks no conferral question, so it names
                # no destination function and has no compositional source; its
                # magnitude question is a different one and stays where Phase 4
                # left it.
                composed, counts, refused, refused_entries = _compose(
                    seeds,
                    walked_hops,
                    act_as,
                    magnitudes,
                    value_plane,
                    conditions,
                    admission,
                    row.principal_addresses,
                )
                for record in refused_entries:
                    # Deduped on (entity, selector): two instances of one row
                    # reaching the same call refused it once, and counting it
                    # twice would double the refusal a reader is shown.
                    withheld_composed.setdefault((record.entity, record.selector), record)
                _pool_composed(composition_candidates, composed)
                for name, count in counts.items():
                    composition_census[name] = composition_census.get(name, 0) + count
                for reason, hits in refused.items():
                    composition_refusals[reason] += hits
                if composed:
                    composed_signals.add(_signal_identity(instance.signal))
        # Reach is MEMBERSHIP, and it is witnessed here. It may not be read off
        # the value map: an entity drops out of that map whenever its dollars
        # are not_determined — an unpriced sheet today, a refused magnitude once
        # the magnitude discipline lands — and deleting a proven fact because an
        # unproven one is missing is the whole error this fold is being repaired
        # for. Priced or not, the row reaches these entities.
        reached.update(value_plane.canonical(key) for key in keys)
        contributions, gaps, cap, unbounded, from_ceilings, non_attributed = _instance_contributions(
            instance, keys, value_plane, transitive=transitive, composed=composed
        )
        unbounded_floors.extend(unbounded)
        census["instances"] += 1
        if _witnessed_magnitude(instance) is None:
            # A composed magnitude is a witness — the DESTINATION's — so it is
            # counted apart from both the calls that carried their own and the
            # calls that carry none. Folding it into either reports a different
            # fact than the one that was proved, and leaving it at zero on the
            # rows that composed says no witness answered where one did.
            #
            # A sheet ceiling is a THIRD answer and gets a third counter for the
            # same reason: it carries no call witness, so it was landing in
            # magnitude_not_witnessed — the population this census says publishes
            # not_determined at the unpriced band's floor, which is exactly what
            # a priced ceiling does not do.
            if from_ceilings and CEILING_KIND_SHEET in from_ceilings.values():
                census["magnitude_sheet_ceiling"] += 1
            else:
                census["magnitude_composed" if composed else "magnitude_not_witnessed"] += 1
        else:
            census["magnitude_witnessed"] += 1
            census["capped" if cap is not None else "within_witnessed_bound"] += 1
        undetermined.extend(gaps)
        if cap is not None:
            magnitude_caps.append(cap)
        for canonical, contribution in contributions.items():
            previous = per_entity.get(canonical)
            if previous is None or contribution > previous:
                per_entity[canonical] = contribution
                ceiling_kinds.pop(canonical, None)
                # The credit goes with the figure it proved. A ceiling a larger
                # contribution has just displaced proves nothing the row
                # publishes, and leaving its signal credited would answer the
                # magnitude question with a number no carrier in the document
                # holds.
                ceiling_signals_by_entity.pop(canonical, None)
                non_attributed_entities.discard(canonical)
            # The bound travels with the figure that stands, and a tie is
            # settled by the weaker of the two claims: an extraction ceiling
            # equal to a witnessed figure is still only a ceiling.
            if canonical in from_ceilings and contribution >= per_entity[canonical]:
                ceiling_kinds[canonical] = from_ceilings[canonical]
                if from_ceilings[canonical] == CEILING_KIND_SHEET:
                    # Ties are the common case and not an edge: several calls on
                    # one node read the same sheet and produce the identical
                    # figure, so each of them proved the number the row
                    # publishes. Only a ceiling STRICTLY beaten above loses its
                    # credit.
                    ceiling_signals_by_entity.setdefault(canonical, set()).add(_signal_identity(instance.signal))
            # Same rule, same direction: an attribution-derived figure tying the
            # standing one revokes the grade, because either candidate may be
            # the number published.
            if contribution >= per_entity[canonical]:
                if canonical in non_attributed:
                    non_attributed_entities.add(canonical)
                else:
                    non_attributed_entities.discard(canonical)

    # Every ceiling label the row is about to publish, checked against the sheet
    # it claims to be — per KEY, which is the only level the cap holds at.
    sheet_ceilings_withheld = _reconcile_sheet_ceilings(ceiling_kinds, per_entity, value_plane)
    for record in sheet_ceilings_withheld:
        ceiling_signals_by_entity.pop(record["entity"], None)

    # One selection over every instance's candidates, not a running MAX: the
    # figure is the same either way, but the selector, destination function,
    # witness state and chain published beside it are the CHOSEN candidate's own
    # and must be taken from it together.
    composition = {key: _select_composed(pool) for key, pool in sorted(composition_candidates.items())}
    # The rule again, on the row's own selection. The pool holds only entries an
    # instance-level pass already admitted, so this changes nothing today — it is
    # here so that the PUBLISHED entry is the one the rule was applied to,
    # whatever a later edit does to the two selection points.
    composition, refused_again = _admit_composed(
        composition, principal_addresses=row.principal_addresses, planes=admission
    )
    for record in refused_again:
        withheld_composed.setdefault((record.entity, record.selector), record)
    refused_composed: dict[str, int] = defaultdict(int)
    for record in withheld_composed.values():
        refused_composed[record.counter_key] += 1
    hop_gaps = [hops[pair] for pair in sorted(hops) if value_plane.canonical(pair[1]) not in reached]
    census["hops_not_determined"] = len(hops)
    census["hops_not_determined_withholding_reach"] = len(hop_gaps)
    withheld_behind = _behind_the_frontier(hop_gaps, closure, conditions, value_plane, reached)
    licensed_out = {key: [fn.as_json() for fn in sorted(rows)] for key, rows in sorted(licensed.items())}
    refusals_out = dict(sorted(refused_composed.items()))
    withheld_out = tuple(withheld_composed[key] for key in sorted(withheld_composed))
    # §7.2 arm 1's conjunct, counted over every entry this row publishes —
    # republished and withheld alike, because the gate claim is published on
    # both and the conjunct qualifies it on both.
    gate_claims = _counted(
        _gate_claim(entry.chain, entry.execution)["state"] for entry in (*composition.values(), *withheld_out)
    )
    composition_report = _composition_report(
        composition, composition_census, dict(composition_refusals), withheld_out, refusals_out, gate_claims
    )
    if not per_entity:
        basis = "proven_no_reach" if proven_no_reach and not undetermined else "not_determined"
        return _RowValue(
            per_entity,
            None,
            basis,
            undetermined,
            proven_no_reach,
            reached,
            magnitude_caps,
            hop_gaps,
            census,
            licensed_out,
            withheld_behind,
            unbounded_floors,
            composition,
            composition_report,
            frozenset(composed_signals),
            withheld_composed_magnitudes=withheld_out,
            refused_composed_magnitudes=refusals_out,
        )
    basis = (
        "witnessed reach magnitude over the "
        + ("code-control" if code_control else "gate-control")
        + " closure, MAX per entity"
        if transitive
        else "per-instance witnessed value, MAX per entity over latest-observation sheets"
    )
    # The coverage gap is NOT written into the basis here. A gap alone does not
    # decide the direction — :func:`_bound_direction` reads the attribution axis
    # beside it — and this function cannot see that axis's verdict, so the
    # direction-bearing sentence is :func:`_coverage_bearing_basis`'s to write.
    if proven_no_reach:
        basis += f"; {len(proven_no_reach)} instance(s) proven_no_reach"
    # A sheet ceiling is capped by its node's own sheet BY CONSTRUCTION — it is
    # that sheet, and the MAX below only ever replaces it with something larger
    # that is no longer a ceiling. The cap therefore holds PER KEY and is checked
    # per key (``tests/test_scoring_redteam.py``'s sheet-ceiling cases); it may
    # NOT be checked on the total, because a row's value sums across every priced
    # host it reaches and legitimately exceeds any single sheet — $4.217B over
    # eight hosts on the reference corpus, more than the largest of them.
    total = round(sum(sorted(per_entity.values())), 6)
    return _RowValue(
        per_entity,
        total,
        basis,
        undetermined,
        proven_no_reach,
        reached,
        magnitude_caps,
        hop_gaps,
        census,
        licensed_out,
        withheld_behind,
        unbounded_floors,
        composition,
        composition_report,
        frozenset(composed_signals),
        ceiling_entities=frozenset(ceiling_kinds),
        sheet_ceiling_entities=frozenset(k for k, v in ceiling_kinds.items() if v == CEILING_KIND_SHEET),
        ceiling_signals=frozenset().union(*ceiling_signals_by_entity.values())
        if ceiling_signals_by_entity
        else frozenset(),
        sheet_ceilings_withheld=sheet_ceilings_withheld,
        non_attributed_entities=frozenset(non_attributed_entities),
        withheld_composed_magnitudes=withheld_out,
        refused_composed_magnitudes=refusals_out,
    )


def _composition_totals(findings: list[dict[str, Any]], subsumed: list[dict[str, Any]]) -> dict[str, Any]:
    """Every row's composition census, summed to the protocol.

    Findings and subsumed rows are rolled up SEPARATELY because a subsumed row is
    usually the same walk seen through a weaker capability: adding the two counts
    one composition twice and publishes twice the recovery. That is the whole
    reason for the split, and it is NOT that a subsumed row's dollars stay out of
    the grade — they do not. A subsumed row's entities that no surviving row
    reaches are charged to the top row's exposure at its own fraction
    (``subsumed_exclusive_value_by_entity``), and on the reference corpus a
    subsumed ``authority.replace`` row's composed ``ethereum::0x657e8c86``
    ($11,358,880.43) enters the top finding's published exposure that way.

    Entities are counted DISTINCT within each population — two findings composing
    the same vault composed one entity — while the dollars are summed per row,
    because that is how they enter the grade: each row is charged what it reaches
    and the exposure budget, not this figure, is what keeps one entity from being
    paid for twice.
    """

    # Per-row counts sum; a per-row MAXIMUM does not, and summing chain lengths
    # across rows would publish an arithmetic artefact as the longest chain the
    # corpus grows.
    maxima = ("longest_composed_chain",)
    # Census keys whose value is itself a count-per-token map. They roll by
    # merging the maps, never by summing them into one number: the whole point
    # of keying a refusal on its reason is that the reasons stay apart.
    breakdowns = (
        "composed_withheld_by_deletability",
        "composed_withheld_by_arm",
        "composed_withheld_by_reason",
        "gate_claim_by_state",
    )

    def roll(rows: list[dict[str, Any]]) -> dict[str, Any]:
        totals: dict[str, int] = defaultdict(int)
        longest: dict[str, int] = dict.fromkeys(maxima, 0)
        refused: dict[str, int] = defaultdict(int)
        broken: dict[str, dict[str, int]] = {key: defaultdict(int) for key in breakdowns}
        entities: set[str] = set()
        withheld_entities: set[str] = set()
        usd = 0.0
        for row in rows:
            census = row.get("reach_composition_census") or {}
            for key, value in census.items():
                if key in ("reading", "act_as_refused", "composed", "composed_usd"):
                    continue
                if key in broken:
                    for token, hits in (value or {}).items():
                        broken[key][token] += int(hits)
                    continue
                if key in longest:
                    longest[key] = max(longest[key], int(value))
                    continue
                totals[key] += int(value)
            for reason, hits in (census.get("act_as_refused") or {}).items():
                refused[reason] += int(hits)
            for entry in row.get("reach_composed_magnitudes") or []:
                entities.add(str(entry["entity"]))
                usd += float(entry["published_usd"])
            for entry in row.get("reach_composed_magnitudes_withheld") or []:
                withheld_entities.add(str(entry["entity"]))
        return {
            **dict(sorted(totals.items())),
            **longest,
            "act_as_refused": dict(sorted(refused.items())),
            **{key: dict(sorted(rows_here.items())) for key, rows_here in broken.items()},
            "rows_composing": sum(1 for row in rows if row.get("reach_composed_magnitudes")),
            "rows_withholding_every_composed_figure": sum(
                1
                for row in rows
                if row.get("reach_composed_magnitudes_withheld") and not row.get("reach_composed_magnitudes")
            ),
            "entities_composed": len(entities),
            "entities_withheld": len(withheld_entities),
            "composed_usd_summed_over_rows": round(usd, 2),
        }

    # How many entities actually take the subsumed-exclusive route into a top
    # row's exposure, counted rather than stated: the sentence below used to
    # assert "one … does so here", a measurement of this corpus baked into a
    # literal and false the moment a second row composes one.
    exclusive: set[str] = set()
    for row in findings:
        exclusive.update(row.get("subsumed_exclusive_value_by_entity") or {})
    charged = sorted(
        exclusive.intersection(
            str(entry["entity"]) for row in subsumed for entry in (row.get("reach_composed_magnitudes") or [])
        )
    )
    charging = (
        f"and {len(charged)} composed subsumed entity(ies) do so here"
        if charged
        else "and no composed subsumed entity does so here — the fold looked, and the two "
        "populations do not meet on this corpus"
    )
    return {
        "findings": roll(findings),
        "subsumed_rows": roll(subsumed),
        "reading": (
            "the composition pass rolled up to the protocol, findings and subsumed rows kept "
            "APART because a subsumed row is usually the same walk under a weaker capability "
            "and summing the two would double one composition and read as twice the recovery. "
            "It is NOT that a subsumed row's dollars stay out of the grade: its entities that "
            "no surviving row reaches charge the top row's exposure at that row's own fraction "
            f"(subsumed_exclusive_value_by_entity), {charging}. licensed_selectors is every "
            "(hop, licensed function) pair a gate-control walk offered; act_as_witnessed is "
            "the subset where the caller is witnessed able to make that call at that "
            "destination; the pairs under act_as_refused are the ones whose magnitude stayed "
            "not_determined and went to confidence instead of the grade. composed_usd is "
            "summed over ROWS and entities are counted distinct, so the two disagree wherever "
            "two rows compose the same entity; the exposure budget, not this figure, is what "
            "stops that entity being paid for twice. act_as_refused standing far above "
            "entities_composed is not a shortfall in the pass but its arithmetic: a licensed "
            "hop composes only where the licensed party is ALSO witnessed makeable to use the "
            "licence, and act_as_refused counts, by reason, every pair where it was not"
        ),
    }


def _named_zeros(counted: dict[str, set[Any]], vocabulary: tuple[str, ...]) -> dict[str, int]:
    """Every token in a CLOSED vocabulary, counted, including the ones at zero.

    A census keyed on a closed set publishes the whole set or it publishes an
    ambiguity: a token missing from the map reads identically as "this rule did
    not fire on this corpus" and "this rule is not in the model", and only the
    first of those is a fact about the protocol. The same rule the credit-path
    reading follows one level up, and the same one ``planes._REDUCTION_COUNTERS``
    follows for the value plane's own counters.

    A token OUTSIDE the vocabulary is not silently dropped. It is a fact the
    document carries and a census that cannot name it would publish a total
    smaller than its own carriers — so it is counted beside the registered ones
    and the caller's vocabulary is what needs fixing.
    """
    out = dict.fromkeys(vocabulary, 0)
    for token, members in counted.items():
        out[token] = len(members)
    return {k: out[k] for k in sorted(out)}


def _sheet_ceiling_totals(
    findings: list[dict[str, Any]],
    subsumed: list[dict[str, Any]],
    credited_by_capability: dict[str, int],
) -> dict[str, Any]:
    """The sheet-ceiling population and its dollars, rolled up to the protocol.

    Every figure here is DERIVED from what the rows published — the per-entity
    records, the refusal tokens in their ``why`` vocabulary, the reconciliation
    withholdings — and from the confidence pass's own credit census. Nothing is
    carried down from the branch that fired: a rollup written at the moment of
    firing would count candidates the per-entity MAX later displaced, which are
    exactly the figures no row publishes.

    Dollars are summed over DISTINCT ENTITIES and not over rows. A sheet ceiling
    is a fact about one node's sheet, so two rows pricing the same node this way
    publish the same number twice and summing them would report twice the money
    that exists. That the two agree is checked rather than assumed: an entity
    whose rows disagree is COUNTED and published, because a disagreement here
    would mean the per-key reconciliation let two different figures stand under
    one claim.

    ``signals_credited_in_confidence`` is the OTHER meter and is deliberately in
    a different unit: the confidence term counts SIGNALS whose magnitude question
    a ceiling answered, while everything above it counts entities and dollars.
    The two are related but not convertible — one node's sheet can answer several
    signals — and the credited population is the standing one, so a ceiling
    displaced by a larger figure or withdrawn by the reconciliation is in neither
    this block's entity count nor that credit.
    """
    populations = (("findings", findings), ("subsumed_rows", subsumed))
    figures: dict[str, set[float]] = defaultdict(set)
    entities_by_capability: dict[str, set[str]] = defaultdict(set)
    by_reason: dict[str, set[str]] = defaultdict(set)
    by_direction: dict[str, set[str]] = defaultdict(set)
    refused: dict[str, set[tuple[str, str]]] = defaultdict(set)
    withheld: set[str] = set()
    rows_publishing = {name: 0 for name, _ in populations}
    for name, rows in populations:
        for row in rows:
            records = row.get("reach_sheet_ceiling_magnitudes") or []
            if records:
                rows_publishing[name] += 1
            for record in records:
                entity = str(record["entity"])
                figures[entity].add(round(float(record["published_usd"]), 2))
                entities_by_capability[str(record["capability"])].add(entity)
                by_reason[str(record["ceiling_reason"])].add(entity)
                by_direction[str(record["bound_direction"])].add(entity)
            for record in row.get("reach_sheet_ceiling_magnitudes_withheld") or []:
                withheld.add(str(record["entity"]))
            for gap in row.get("undetermined_instances") or []:
                why = str(gap.get("why") or "")
                if not why.startswith(SHEET_CEILING_REFUSED_PREFIX):
                    continue
                reason = why[len(SHEET_CEILING_REFUSED_PREFIX) :].removesuffix(")")
                # Deduped on the CALL, so two rows reaching one call through two
                # principals report the one refusal that happened rather than two.
                refused[reason].add((str(gap.get("entity")), str(gap.get("function"))))
    disagreeing = sorted(key for key, seen in figures.items() if len(seen) > 1)
    # An entity reached by two code-control capabilities is priced this way under
    # BOTH, so the capability buckets sum past the distinct-entity count and a
    # reader adding them up over-counts the population. Counted rather than left
    # to be noticed: the dollars are deduped and the breakdown is not, and only
    # one of those two facts was published.
    shared_capability = sorted(
        key for key in figures if sum(1 for members in entities_by_capability.values() if key in members) > 1
    )
    return {
        "entities_priced_from_a_sheet_ceiling": len(figures),
        "entities_by_capability": {k: len(v) for k, v in sorted(entities_by_capability.items())},
        "entities_in_more_than_one_capability": len(shared_capability),
        "ceiling_usd_over_distinct_entities": round(sum(max(seen) for _, seen in sorted(figures.items())), 2),
        "entities_publishing_more_than_one_figure": disagreeing,
        "entities_by_ceiling_reason": _named_zeros(by_reason, P.CEILING_ADMITTING_REASONS),
        "entities_by_bound_direction": _named_zeros(by_direction, SHEET_CEILING_BOUND_DIRECTIONS),
        "rows_publishing_a_sheet_ceiling": rows_publishing,
        "calls_refused_by_reason": _named_zeros(refused, CEILING_REFUSAL_REASONS),
        "entities_withheld_on_sheet_reconciliation": len(withheld),
        "signals_credited_in_confidence": sum(credited_by_capability.values()),
        "signals_credited_by_capability": dict(sorted(credited_by_capability.items())),
        "reading": _sheet_ceiling_totals_reading(figures, refused, withheld, disagreeing, shared_capability),
    }


def _sheet_ceiling_totals_reading(
    figures: dict[str, set[float]],
    refused: dict[str, set[tuple[str, str]]],
    withheld: set[str],
    disagreeing: list[str],
    shared_capability: list[str],
) -> str:
    """The rollup's account of itself, with every count taken from its own data."""
    admitted = len(figures)
    refusals = sum(len(calls) for calls in refused.values())
    head = (
        f"{admitted} entity(ies) are priced from their own sheet here and "
        f"{refusals} code-control call(s) asked for a sheet ceiling and were refused one, "
        "counted by the reason the SHEET gave — 'no balance was ever observed at this node', "
        "'the price lookup never answered' and 'the asset list was read at its page cap' are "
        "the work of three different pipelines and a reader who cannot tell them apart cannot "
        "act on any of them"
        if admitted or refusals
        else "no entity is priced from its own sheet here and no code-control call was refused "
        "one: the branch had nothing to fire on, which is a measured zero and not a silence"
    )
    reconciled = (
        f" {len(withheld)} entity(ies) carried a figure that did not reconcile against the sheet "
        "it claimed to be, so the ceiling LABEL was withheld there while the dollars stand"
        if withheld
        else " Every figure reconciled against the sheet it claims to be; none was withheld"
    )
    disagreement = (
        f" {len(disagreeing)} entity(ies) publish more than one figure across rows, which the "
        "per-key reconciliation is supposed to make impossible — the total takes the largest and "
        "names them here rather than absorbing the disagreement"
        if disagreeing
        else " No entity publishes two different figures across rows, so the total double-counts nothing"
    )
    # The dollars are deduped and the capability breakdown is NOT, so the two
    # answer different questions and only saying so keeps a reader from adding
    # the buckets up. Every count in the reading is of the entity population;
    # entities_by_capability counts memberships in it.
    buckets = (
        f" The dollars, not the breakdown: {len(shared_capability)} entity(ies) are priced this way "
        "under MORE THAN ONE code-control capability and appear in that many buckets, so "
        "entities_by_capability sums past the distinct-entity count above and is a count of "
        "memberships rather than of entities"
        if shared_capability
        else " No entity is priced this way under more than one capability, so the "
        "entities_by_capability buckets happen to sum to the distinct-entity count here — an "
        "arithmetic coincidence of this corpus and not a property of the breakdown"
    )
    return (
        head
        + "."
        + reconciled
        + "."
        + disagreement
        + "."
        + buckets
        + ". The dollars are an AT-MOST and never an amount: they bound what replacing each "
        "node's code can move AT THAT NODE, they say nothing about what those nodes in turn "
        "govern, and they are deliberately outside exposure_usd — an upper bound on a move "
        "nobody witnessed is not expected loss, and charging one would displace a row that "
        "measured a real extraction. They must never be rendered as dollars at risk"
    )


def _execution_carriers(node: Any) -> Iterator[dict[str, Any]]:
    """Every published dict carrying a ``proving_execution`` block, wherever it sits.

    Walked structurally rather than read off the two list names the composition
    rule uses today: a census that names its carriers cannot count a carrier
    added after it was written, and an execution block this document publishes
    but the census never looked at is exactly the silent miss the census exists
    to stop.
    """
    if isinstance(node, dict):
        if isinstance(node.get(PROVING_EXECUTION_KEY), dict):
            yield node
        for value in node.values():
            yield from _execution_carriers(value)
    elif isinstance(node, list):
        for item in node:
            yield from _execution_carriers(item)


def _execution_fault_census(findings: list[dict[str, Any]], subsumed: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The published magnitudes whose proving execution could not be read, or ``None``.

    ``None`` where the walk covered every published execution block and none of
    them carried a registered fault reason — a completed count of zero, which is
    why the document omits the field rather than publishing an empty census.

    The reasons counted here are :data:`EX.FAULT_REASONS`, the subset
    :func:`_admit_composed` takes the ``withheld`` arm on. That arm fires BEFORE
    the deletability join is consulted, so a faulted entry loses its dollars
    however the join answered — which is why a fault is a fact about the GRADE
    and not only about one entry, and why it is announced at the document's top
    level instead of being left to be found by reading forty blocks.

    Nothing here names a cause. A body that could not be read is not a store
    that was unavailable, and the four reasons are not even one situation
    between them: ``transcript_unstored`` is a record that was never written,
    while ``fetch_failed`` is a read that did not come back. They are published
    apart and counted apart.
    """
    populations = (("findings", findings), ("subsumed_rows", subsumed))
    examined = 0
    reasons: list[str] = []
    by_population: dict[str, int] = {name: 0 for name, _ in populations}
    entities: set[str] = set()
    for name, rows in populations:
        for carrier in _execution_carriers(rows):
            examined += 1
            reason = carrier[PROVING_EXECUTION_KEY].get("reason")
            if reason not in EX.FAULT_REASONS:
                continue
            reasons.append(str(reason))
            by_population[name] += 1
            entity = carrier.get("entity")
            if isinstance(entity, str):
                entities.add(entity)
    if not reasons:
        return None
    return {
        # The machine-checkable marker. Not a ``grade_state`` value — see
        # ``utils.scoring_status.GRADE_FAULT_DEGRADED`` for why the two
        # vocabularies are kept apart.
        "grade_qualifier": GRADE_FAULT_DEGRADED,
        "records_faulted": len(reasons),
        # The denominator, so a reader can tell one unreadable block in forty
        # from forty in forty without counting them.
        "execution_records_examined": examined,
        "faulted_by_reason": _counted(reasons),
        "faulted_by_population": by_population,
        "entities_affected": sorted(entities),
        "registered_fault_reasons": sorted(EX.FAULT_REASONS),
        "reading": (
            "every published magnitude names the execution that proved it — or, where the proof "
            "was never a call, the registered reason no execution names it: a sheet ceiling under "
            "reach_sheet_ceiling_magnitudes[] is proven by a BALANCE OBSERVATION of the controlled "
            "node and carries magnitude_not_proven_by_a_call, which is not a fault and is counted "
            "in execution_records_examined below without being counted as one. records_faulted "
            "of them name a typed reason that execution could not be READ. Each one was withheld "
            "by the composition rule's fault arm whatever the authority-deletability join "
            "licensed, so grade_lambda, grade_exposure and confidence_pct here were computed over "
            "fewer composed figures than the same database state yields when every transcript "
            "body reads. THIS DOCUMENT MUST NOT BE COMPARED AGAINST A FAULT-FREE RUN: a moved "
            "grade is not evidence the protocol changed. What is proven is that these bodies "
            "could not be read on this fold — nothing here proves the object storage was "
            "unavailable, and faulted_by_reason keeps the registered situations apart because a "
            "transcript that was never stored and a fetch that did not return are different "
            "facts. entities_affected is the distinct entity of each faulted carrier, published "
            "so the census can be checked against the rows rather than taken on the fold's word"
        ),
    }


def _execution_fault_warning(census: dict[str, Any]) -> dict[str, Any]:
    """The census's top-level warning, with its counts derived from the census."""
    breakdown = ", ".join(f"{reason} x{hits}" for reason, hits in census["faulted_by_reason"].items())
    return {
        "kind": "execution_evidence_unreadable",
        "note": (
            f"{census['records_faulted']} of {census['execution_records_examined']} published "
            f"proving-execution records could not be read: {breakdown}. Every one of them was "
            "withheld by the composition rule's fault arm regardless of what the "
            "authority-deletability join licensed, so the grade, exposure and confidence in this "
            "document moved with what could be read here and not only with the protocol. Do not "
            "compare this document against a fault-free run. This is not proof the artifact store "
            "was unavailable — what is proven is that these bodies could not be read on this fold; "
            "see execution_evidence_faults for the per-reason census"
        ),
        "records_faulted": census["records_faulted"],
        "faulted_by_reason": dict(census["faulted_by_reason"]),
    }


def _signal_identity(signal: FunctionSignal) -> tuple[Any, ...]:
    """What names one signal row across the fold and the confidence pass.

    ``contract_id`` is part of it because split-proxy secondary implementations
    share a ``deployment_address`` and are legitimately different contracts.
    """
    return (signal.contract_id, signal.chain, signal.deployment_address, signal.selector, signal.claim_id)


def _counted(values: Iterable[str]) -> dict[str, int]:
    """A sorted count per distinct token. Empty where nothing was counted."""
    out: dict[str, int] = defaultdict(int)
    for value in values:
        out[value] += 1
    return dict(sorted(out.items()))


# Why each arm withheld, for the CENSUS's account of ``composed_withheld``. The
# sentence these replace gave a single cause for a counter three different arms
# feed — "because the route they publish is not the route the proof took and
# nothing proved this principal could have issued the proven call itself" — and
# both halves are the two clauses B1-N1 removed from the per-entry reading,
# failing on the same carriers: there is no proven route to differ from on the
# transport-fault arm, no typed route finding either way on the unclassified
# arm, and the fault arm is reached BEFORE the join is consulted, so it can
# publish ``deletable`` beside its own refusal. Rolling three findings into one
# cause at the aggregate is the same collapse the per-entry fix removed, one
# level up.
#
# ``ARM_GATE_ONLY`` is keyed on the ROUTE TOKEN and not on the arm, because the
# arm fires on two of them (:func:`_admit_composed`) and they are two different
# findings about the traversed body: one says the intermediate computes the
# quantity, the other says it pins the counterparty. Keyed on the arm alone, a
# target-constrained carrier read "AUTHORING" in the census beside its own
# ``withheld_reason`` naming the other token — the same disagreement between two
# adjacent blocks, one level down. The other two arms do not read the route at
# all: the transport fault is a finding about neither witness, and the
# unclassified arm's own reason IS the route's.
_GATE_ONLY_ROUTE_CAUSES = {
    P.ROUTE_AMOUNT_AUTHORED: (
        "a route witnessed AUTHORING what the destination call carries, so the destination's own "
        "figure is not a figure for this route"
    ),
    P.ROUTE_TARGET_CONSTRAINED: (
        "a route witnessed PINNING which counterparty the destination call pays, so the "
        "destination's own figure is not a figure this caller can direct"
    ),
}
_ARM_ONLY_CAUSES = {
    ARM_WITHHELD: (
        "an execution that could not be READ at all — which is a finding about neither the route "
        "nor the join: both were computed before this arm was reached and are published, and a "
        "deletability licence standing among them does not release the figure"
    ),
    ARM_NOT_DETERMINED: (
        "a route that earned no typed finding in either direction, with no arm left to fall through to"
    ),
}
# Every (arm, route token) pair that has a registered cause, in the order the
# census lists them. There is no default: a pair absent here raises rather than
# reaching the document through a sentence nobody wrote for it.
_WITHHELD_CAUSE_ORDER: tuple[tuple[str, str | None], ...] = tuple(
    (ARM_GATE_ONLY, state) for state in (P.ROUTE_AMOUNT_AUTHORED, P.ROUTE_TARGET_CONSTRAINED)
) + tuple((arm, None) for arm in COMPOSITION_ARMS if arm in _ARM_ONLY_CAUSES)


def _withheld_cause_key(record: "_WithheldComposition") -> tuple[str, str | None]:
    """The (arm, route token) pair this record's census cause is keyed on."""
    return (record.arm, record.route.state if record.arm == ARM_GATE_ONLY else None)


def _withheld_cause(key: tuple[str, str | None]) -> str:
    arm, route_state = key
    if arm == ARM_GATE_ONLY:
        return _GATE_ONLY_ROUTE_CAUSES[cast(str, route_state)]
    return _ARM_ONLY_CAUSES[arm]


def _withheld_cause_clause(withheld: tuple["_WithheldComposition", ...]) -> str:
    """The census's account of ``composed_withheld``, derived from the arms and
    route tokens that actually fired on THIS row rather than authored once for
    all of them."""
    counts: dict[tuple[str, str | None], int] = defaultdict(int)
    for record in withheld:
        counts[_withheld_cause_key(record)] += 1
    fired = [(key, counts[key]) for key in _WITHHELD_CAUSE_ORDER if counts.get(key)]
    if not fired:
        return (
            "composed_withheld is 0 here: no candidate that cleared the witnesses above lost its "
            "figure to the composition rule, which is a count of nothing and not a claim that the "
            "rule was not asked"
        )
    return (
        "composed_withheld is a LATER and different refusal: those candidates cleared every "
        "witness above and then lost their figure to the composition rule — "
        + "; ".join(f"{hits} to {_withheld_cause(key)}" for key, hits in fired)
        + f". The {len(_WITHHELD_CAUSE_ORDER)} registered causes are not interchangeable. "
        "composed_withheld_by_arm beside this separates the arms, and because one arm withholds "
        "under either of two route tokens, composed_withheld_by_reason is what separates those "
        "two — each entry's own withheld_reason names the token it was refused under"
    )


def _composition_report(
    composed: dict[str, _ComposedMagnitude],
    census: dict[str, int],
    refusals: dict[str, int],
    withheld: tuple[_WithheldComposition, ...],
    refused_magnitudes: dict[str, int],
    gate_claims: dict[str, int],
) -> dict[str, Any]:
    """What composition proved, and — in the same object — what it refused.

    A report listing only the entities that composed would read as a coverage
    figure. The refusals are the larger population by an order of magnitude on
    the reference corpus and they are the honest denominator: a licensed hop that
    composed nothing is a hop whose magnitude is still not_determined, and the
    reason it stayed there is the difference between "no witness exists" and
    "this fold declined to look".
    """
    return {
        **{key: value for key, value in sorted(census.items())},
        # Per-ENTITY, so it lines up with reach_composed_magnitudes. The
        # per-instance counts above are over (hop, selector) pairs and two
        # instances reaching one destination raise them twice.
        "composed": len(composed),
        "composed_usd": round(sum(sorted(entry.usd for entry in composed.values())), 2),
        # What the three-arm rule refused, in the same per-entity units. Beside
        # the count of what it admitted and never instead of it: a report that
        # published only the survivors would read as a coverage figure over a
        # population the rule had already narrowed.
        "composed_withheld": len(withheld),
        # inv. 13's disclosure hook. Keyed on the deletability verdict's STATE
        # and reason together, so a join that ran and found no row is counted
        # apart from a join whose authority could not be resolved. A protocol
        # that makes its gating authority unresolvable lands in the second
        # bucket and its published figure falls — so the bucket has to be
        # visible, or obscuring evidence would look like an absent finding.
        "composed_withheld_by_deletability": refused_magnitudes,
        "composed_withheld_by_arm": _counted(record.arm for record in withheld),
        "composed_withheld_by_reason": _counted(record.reason for record in withheld),
        # §7.2 arm 1's caller conjunct over every entry this row publishes. An
        # entry the proof was admitted for a DIFFERENT caller at keeps its gate
        # claim on the act-as witness and is counted apart, so "the gate claim
        # transferred" is never a silent default.
        "gate_claim_by_state": gate_claims,
        # Chain length is unbounded by the rule and bounded by the corpus, and a
        # reader has no other way to see the day it grows. 1 is a direct call
        # from the seized node; 2 is the first chain that traverses a node the
        # principal seized nothing on.
        "longest_composed_chain": max((len(entry.chain) for entry in composed.values()), default=0),
        "act_as_refused": dict(sorted(refusals.items())),
        "reading": (
            "licensed_selectors counts every (hop, licensed function) pair the walk offered "
            "composition. act_as_witnessed is the subset where the CALLER is witnessed able to "
            "be made to call that selector at that destination — the step a licence does not "
            "imply and without which a magnitude is priced on membership alone. It is witnessed "
            "under either of two shapes, named per step: a restricted, authority-gated function "
            "of the caller calling that selector on a state variable of its own read on-chain "
            "holding the destination, or — where that call site takes its callee as a "
            "parameter, so no storage of the caller CAN name the address — the destination's "
            "own access-control list naming this caller as an accepted caller of that selector "
            "by an enumerated role. Past the first hop the calling function must additionally "
            "be one the previous hop admitted, matched on that function's own selector, "
            "because no hop inherits its predecessor's authority: the finding's seized gate is "
            "spent at hop 1 and only there. The two per-site conjuncts do NOT both survive "
            "that boundary and neither is conservative-only. The DELEGATION conjunct is not "
            "applied past hop 1 — the licence there is the previous hop's admitted selector, "
            "and a direct msg.sender gate on the intermediate is exactly the shape such a "
            "chain runs through; a step admitted without the delegation witness says so on "
            "itself, under admitted_without_a_delegation_witness, so the published basis "
            "names the conjunct that was not applied rather than dropping it silently. A call "
            "site whose calling function needs no gate is refused "
            "at EVERY hop, and not because the rule is conservative: an open function is one "
            "anyone can call, so the value it moves is not conferred by the seized gate and "
            "belongs to that function's own finding. destination_magnitude_witnessed "
            "is the subset of those "
            "whose destination function also carries its own flow.out witness. composed is the "
            "distinct entities that cleared every one, and every figure they carry is a ceiling "
            "on one call rather than a floor. One entity may clear all three under MORE THAN "
            "ONE selector, and composed counts it once: two selectors at one entity are two "
            "independent calls, so the dollars published are the largest of them — a max of "
            "ceilings, never their sum and never the lower of the two, which is the rule for "
            "two distillations of one quantity and not for two calls. Where the largest is a "
            "tie, the entry names which candidates tied and by what rule the published "
            "selector, destination_function and act_as_chain were picked out of them, under "
            "composed_selector_tie; null there is the proven 'one candidate'. Everything in "
            "act_as_refused stayed not_determined and is charged to confidence. "
            + _withheld_cause_clause(withheld)
            + ". Each keeps its act-as chain and publishes its gate_claim and proving_execution "
            "blocks whatever state those reached — a withheld figure retracts neither question, "
            "and where either could not be answered the block carries its own typed reason rather "
            "than going quiet. They are listed per row under "
            "reach_composed_magnitudes_withheld. gate_claim_by_state is a DIFFERENT axis again and "
            "cuts across both populations: it says, per entry, whether the execution that proved "
            "the destination's figure was admitted for the caller this entry's chain names. Where "
            "it was not, the gate claim rests on the act-as witness alone and says so — an "
            "authorization check reads msg.sender, so a proof admitted for another address does "
            "not establish this one"
        ),
    }


@dataclass(frozen=True)
class _DestinationMagnitude:
    """A ``flow.out`` witness at one destination function, as the fold received it.

    ``execution`` is the call that PROVED ``usd`` — caller, target, selector, raw
    calldata, pinned height, seeded-or-not — read off the destination signal's own
    gate rather than reconstructed here. It travels WITH the figure because the
    two are one fact: a magnitude whose execution is not_determined is a number
    with no account of itself, and the composition rule that decides whether the
    figure survives a route the proof never took cannot be written without it.

    ``attribution_derived`` is a property rather than a stored field so the state
    stays the single source of truth: an attribution-derived figure is exactly one
    whose magnitude state says so, and a second copy of that fact could disagree
    with the first.
    """

    state: str
    usd: float
    function: str
    execution: EX.ProvingExecution

    @property
    def attribution_derived(self) -> bool:
        """Whether the figure bounds its principal from ABOVE and never below.

        True on the attribution path, where a constant-amount probe credited a
        holder's whole priced balance. A row summing such contributions has not
        earned a ">=" band, whatever its coverage looks like.

        The registry it reads is the DIRECTION set, which also carries the sheet
        ceiling. That is not a widening here: a ``_DestinationMagnitude`` is
        built only from a destination function's own witnessed ``flow.out``
        figure, and a sheet ceiling — proven by a balance observation, not by a
        call — never constructs one, so the ceiling state cannot reach this
        property.
        """
        return self.state in MAGNITUDE_STATES_UPPER_BOUNDING


def _destination_magnitudes(signals: list[FunctionSignal]) -> dict[tuple[str, str], _DestinationMagnitude]:
    """Every witnessed ``flow.out`` magnitude, keyed by (entity, selector).

    This is the same 55-row population the fold already prices flow rows from —
    ``distill._flow_reach``'s ``_proven_number`` is its only constructor — read a
    second time as what a DESTINATION function is proven to move. Composition
    adds no witness; it joins an existing one to a reach that was already proven.

    Keyed on the selector because that is what a role licenses. A destination
    function with no selector (fallback, receive) can never be the far end of a
    licence and is left out.
    """
    out: dict[tuple[str, str], _DestinationMagnitude] = {}
    for signal in signals:
        if signal.claim_id != "flow.out" or not signal.selector.startswith("0x"):
            continue
        magnitude = _gate(signal, "reach_magnitude_usd")
        if not magnitude.is_determined or not _is_number(magnitude.value):
            continue
        key = (entity_key(signal.chain, signal.deployment_address), signal.selector.lower())
        usd = float(magnitude.value)  # type: ignore[arg-type]  # _is_number narrows it
        previous = out.get(key)
        # Two signals on one selector are the same function distilled twice; the
        # LOWER figure is the one both witnesses support. The execution is taken
        # from the SAME signal as the figure, never merged across the two: it is
        # that call's account of itself, and pairing one signal's dollars with
        # another's caller would publish an execution that proved a different
        # number.
        if previous is None or usd < previous.usd:
            out[key] = _DestinationMagnitude(magnitude.state, usd, signal.function_name, _signal_execution(signal))
    return out


def _signal_execution(signal: FunctionSignal) -> EX.ProvingExecution:
    """The execution this signal's magnitude was proven by, or the typed reason
    there is none.

    A gate this fold cannot read is not an execution it may assume. ``_gate``
    already degrades an unrecognised token to ``not_determined``, and a
    ``not_determined`` envelope carries no payload — so both of those land on
    :data:`EX.REASON_NOT_PERSISTED`, the same state a row written before the
    record existed lands on. Absence never becomes a match, an empty caller, or
    an unseeded probe.
    """
    gate = _gate(signal, PROVING_EXECUTION_KEY)
    payload = gate.value if isinstance(gate.value, dict) else {}
    ptr = payload.get("transcript_ptr")
    verdict_id = payload.get("effect_verdict_id")
    # The two POINTERS survive the negative branch. They are the row's own
    # identity, not part of the record, and they are exactly what a reader needs
    # in order to go and look at the transcript the record is missing from —
    # dropping them would turn a traceable gap into an untraceable one.
    if gate.state != EX.GATE_STATE_RECORDED:
        reason = payload.get("reason")
        return EX.not_determined(
            reason if reason in EX.NOT_DETERMINED_REASONS else EX.REASON_NOT_PERSISTED,
            transcript_ptr=ptr if isinstance(ptr, str) else None,
            effect_verdict_id=verdict_id if isinstance(verdict_id, int) else None,
        )
    return EX.from_residue(
        payload,
        transcript_ptr=ptr if isinstance(ptr, str) else None,
        effect_verdict_id=verdict_id if isinstance(verdict_id, int) else None,
    )


@dataclass(frozen=True)
class _AdmissionPlanes:
    """The two witnesses the composition rule decides an arm from.

    Bundled because they travel together through five call sites and neither is
    ever consulted without the other: one says whether the principal could have
    authored the destination's calldata itself, the other says what the body the
    chain traverses does to that calldata on the way.
    """

    deletability: P.DeletabilityPlane
    routes: P.RouterFlowPlane


@dataclass(frozen=True)
class _WithheldComposition:
    """A composed candidate whose FIGURE the rule refused, and everything else it keeps.

    Arm 2 withholds the magnitude and nothing else. The gate claim transfers —
    ``isAuthorized(msg.sender, msg.sig)`` reads no argument, so a routing
    mismatch says nothing about it — and the act-as chain that carries it is
    published here in full, beside the execution that was actually run and the
    typed reason the dollars did not survive the difference between them.

    There is no ``published_usd`` and no witnessed figure of any kind. A refusal
    that still prints the number it refused has published it.
    """

    entity: str
    selector: str
    function: str
    chain: tuple[P.ActAsStep, ...]
    execution: EX.ProvingExecution
    arm: str
    reason: str
    route: P.RouteClassification
    deletability: P.DeletabilityVerdict

    def __post_init__(self) -> None:
        # An arm with no registered sentence would otherwise reach the published
        # reading through a default, which is a claim nobody wrote for it.
        if self.arm not in _WITHHELD_ARM_READINGS:
            raise ValueError(f"no withheld reading is registered for arm {self.arm!r}")

    @property
    def counter_key(self) -> str:
        """The ``(state, reason)`` pair the refusal counter keys on.

        BOTH halves, never the reason alone: the deletability vocabulary mixes
        one earned negative (a join that ran and returned no row) with three
        undetermined kinds, and bucketing them together would put a proven fact
        and a disclosed unknown under one count — the inv. 1 collapse the whole
        join exists to prevent, relocated into the counter.
        """
        return f"{self.deletability.state}/{self.deletability.reason}"

    def as_json(self) -> dict[str, Any]:
        return {
            "entity": self.entity,
            "destination_function": self.function,
            "selector": self.selector,
            "arm_taken": self.arm,
            "withheld_reason": self.reason,
            # Spelled, not omitted: a missing key reads as a field nobody filled
            # in, and this one is a refusal somebody made.
            "published_usd": None,
            "proving_execution": self.execution.as_json(),
            "route_comparison": EX.route_comparison(
                self.execution,
                claimed_caller=self.chain[-1].caller if self.chain else None,
                claimed_target=self.chain[-1].destination if self.chain else None,
                claimed_selector=self.chain[-1].calling_selector if self.chain else None,
            ),
            # The gate claim, which survives the refusal — qualified by its own
            # caller conjunct rather than by the arm that took the figure.
            "gate_claim": _gate_claim(self.chain, self.execution),
            "act_as_chain": [step.as_json() for step in self.chain],
            "act_as_chain_length": len(self.chain),
            "route_classification": self.route.as_json(),
            "authority_deletability": self.deletability.disclosure(),
            "reading": _WITHHELD_OPENING + _WITHHELD_ARM_READINGS[self.arm] + _WITHHELD_CLOSING,
        }


def _gate_claim(chain: tuple[P.ActAsStep, ...], execution: EX.ProvingExecution) -> dict[str, Any]:
    """§7.2 arm 1's conjunct, EVALUATED, for one entry.

    The arm is "gate claims transfer ON CALLER MATCH", and the conjunct is not
    satisfied by publishing ``caller_matches`` and leaving a reader to apply it:
    an entry that says nothing about the comparison reads as one where it
    passed. So the outcome is published under its own three-state token, on the
    republished entries and the withheld ones alike, and it is counted per row.
    """
    return EX.gate_claim(execution, claimed_caller=chain[-1].caller if chain else None)


def _admit_composed(
    composed: dict[str, _ComposedMagnitude],
    *,
    principal_addresses: Iterable[str],
    planes: _AdmissionPlanes,
) -> tuple[dict[str, _ComposedMagnitude], list[_WithheldComposition]]:
    """The composition rule's three arms, applied to the SELECTED entries.

    Applied to the returned ``composed`` dict and never inside the candidate
    pool. Filtering the pool lets the selection promote a different candidate at
    the same entity, so a withheld figure would be replaced by the next one down
    rather than withheld — the document is not monotone under withholding and
    dropping ten entries once yielded thirty-six.

    The arms, in the order they are asked:

    1. **The gate claim transfers ACROSS A ROUTE MISMATCH, and its caller
       conjunct is evaluated separately.** It is not one of the branches below:
       every outcome publishes the act-as chain, because an authorization check
       reads ``msg.sender`` and ``msg.sig`` and no ARGUMENT, so a proof that
       entered by a different path still exercised the same check. That argument
       does NOT carry across a different CALLER — ``msg.sender`` is exactly what
       the check reads — so the caller half is asked per entry by
       :func:`_gate_claim` and published as its own three-state outcome beside
       the chain. A mismatch qualifies the claim; it does not retract it, because
       the chain is the act-as plane's witness and is established without any
       transcript.
    2. **The magnitude is withheld** where the figure's own execution could not
       be reached at all (a transport fault — ``ARM_WITHHELD``), or where the
       body the chain traverses is witnessed authoring the destination call's
       arguments (``ARM_GATE_ONLY``, under the route classification's own typed
       token).
    3. **The direct path is republished** where the deletability join proves
       this principal can author the destination's calldata itself. The route
       published is then the one the probe ran, and the entry names the
       ``function_principals`` row that licensed it.

    And there is no fourth: a candidate whose route earns neither typed token
    and whose principal the join did not prove lands on ``ARM_NOT_DETERMINED``
    with its figure withheld. There is no ``else`` that publishes, and no branch
    reads a hop count, a selector name or a contract's shape.

    The fault scoping is the load-bearing detail. ``execution_record_not_persisted``
    is NOT a fault: the record is derivable from the transcript the verdict
    points at, and refusing on it withholds every figure in the corpus — the
    blanket refusal already measured and refuted.
    """
    kept: dict[str, _ComposedMagnitude] = {}
    withheld: list[_WithheldComposition] = []
    addresses = tuple(principal_addresses)
    for key, entry in sorted(composed.items()):
        last = entry.chain[-1] if entry.chain else None
        route = planes.routes.classify(
            last.caller if last else "",
            last.calling_selector if last else None,
            entry.selector,
        )
        verdict = P.authority_deletability(planes.deletability, addresses, key, entry.selector)
        if entry.execution.reason in EX.FAULT_REASONS:
            arm, reason = ARM_WITHHELD, entry.execution.reason
        elif verdict.is_deletable:
            kept[key] = replace(entry, arm_taken=ARM_REPUBLISHED_DIRECT, deletability=verdict, route=route)
            continue
        elif route.state in (P.ROUTE_AMOUNT_AUTHORED, P.ROUTE_TARGET_CONSTRAINED):
            arm, reason = ARM_GATE_ONLY, route.state
        else:
            arm, reason = ARM_NOT_DETERMINED, cast(str, route.reason)
        withheld.append(
            _WithheldComposition(
                entity=entry.entity,
                selector=entry.selector,
                function=entry.function,
                chain=entry.chain,
                execution=entry.execution,
                arm=arm,
                reason=reason,
                route=route,
                deletability=verdict,
            )
        )
    return kept, withheld


def _compose(
    seeds: set[str],
    hops: list[_WalkedHop],
    act_as: P.ActAsPlane,
    magnitudes: dict[tuple[str, str], _DestinationMagnitude],
    value_plane: P.ValuePlane,
    conditions: P.ConditionPlane,
    admission: _AdmissionPlanes,
    principal_addresses: Iterable[str],
) -> tuple[dict[str, _ComposedMagnitude], dict[str, int], dict[str, int], list[_WithheldComposition]]:
    """The gate-control magnitude the destination's own witness supplies (Phase 6).

    Phase 4 floored every gate-control magnitude to ``not_determined`` because
    nothing proved how much the reach moves. For a licensed hop that is
    recoverable without new evidence: the destination function the gate licenses
    may already carry its OWN ``flow.out`` magnitude witness, and that witness
    bounds what a call to it moves whoever makes the call.

    Three witnesses, and all three are required:

    1. the LICENCE (W4a) — the role the hop walks is witnessed licensing this
       named selector at this destination;
    2. the destination's ``flow.out`` MAGNITUDE — a fork-proven figure for that
       selector, reused, never re-derived;
    3. the ACT-AS step, at EVERY hop from the seized node to the destination —
       the caller is witnessed able to be made to call that selector THERE,
       under either of the two shapes :class:`P.ActAsPlane` admits: a state
       variable of the caller read on-chain holding the next node, or — where
       the call site takes its callee as a parameter, so no storage of the
       caller can name it — the next node's own access-control list naming this
       caller as an accepted caller of that selector by an enumerated role.

    (3) is the one the licence does not imply and the one this pass exists to
    enforce. A role saying N MAY call D says nothing about whether the principal
    can make N do it: seizing an authority pointer on N buys N's own restricted
    functions, and unless one of those is witnessed calling D, the path stops at
    N. Pricing on membership alone is the banned move at one remove. What that
    costs on the reference corpus is visible in the census rather than in any
    one shape: the two rows seized at a RolesAuthority carry eleven and three
    licensed hops and publish ``caller_not_reachable_from_the_seized_node`` on
    all of them — the walk never reaches those hops' callers, so no witness
    shape is ever asked, and their magnitude stays not_determined for a reason
    upstream of this pass.

    The path is walked breadth-first from the seeds, which are act-as reachable
    by definition (they are the entities the finding's own signal was witnessed
    on). A destination inherits reachability only through a hop that carries its
    own act-as witness, so a chain is only ever as strong as its weakest step.

    MULTI-HOP: no hop inherits its predecessor's authority. The finding's seized
    gate is spent at hop 1 and only there — at a SEED, never at a node some hop
    was witnessed reaching — which is where the plane's ``restricted`` +
    delegated conjuncts are the licence. Past it the principal has seized
    nothing on the intermediate; it arrives as whoever the previous hop
    admitted, so the licence at hop k+1 is that the intermediate's calling
    function is one hop k admitted, matched on that function's OWN selector
    because a function name does not identify a function. ``chains`` holds those
    admitted functions per node, keyed by that selector, each with the path that
    admitted it.

    The plane's two per-site conjuncts are NOT symmetric past hop 1, and neither
    is "conservative-only". The DELEGATION conjunct is not applied there: the
    licence is the previous hop's admitted selector, and a direct ``msg.sender``
    gate on the intermediate is exactly the shape such a chain runs through. A
    step admitted without that witness carries
    ``admitted_without_a_delegation_witness: true``, so the conjunct that was
    not applied is named on the step rather than dropped silently. The OPENNESS
    conjunct IS applied at every hop, and not out of caution — an open function
    is one anyone can call, so the value it moves is not conferred by the seized
    gate and belongs to that function's own finding.

    Where one entity offers more than one licensed selector carrying a
    magnitude, the entry published is chosen by :func:`_composed_order` and the
    losers tied at the same figure are published beside it: the dollars are a
    max of ceilings, but the selector, function, witness state and chain are one
    call's account of itself and are taken from the chosen candidate together.
    """
    census: dict[str, int] = dict.fromkeys(
        (
            "licensed_hops",
            "licensed_selectors",
            "destination_magnitude_witnessed",
            "act_as_witnessed",
            "composed",
        ),
        0,
    )
    refusals: dict[str, int] = defaultdict(int)
    by_caller: dict[str, list[_WalkedHop]] = defaultdict(list)
    for hop in hops:
        if hop.licensed:
            census["licensed_hops"] += 1
            by_caller[hop.caller].append(hop)

    candidates: dict[str, list[_ComposedMagnitude]] = {}
    # Per node, every function of it a hop admitted — keyed by that function's
    # own SELECTOR — and the chain that admitted it. A node entered under two
    # functions carries two chains, and each licensed hop out of it is published
    # with the one whose entry function that hop is issued from: the chain must
    # BE the path, not a path. A SEED's map is never READ — a hop landing on a
    # seed still records its entry, but a seed is entered by the finding's own
    # seized gate, so both the via constraint and the prefix lookup below skip
    # it.
    chains: dict[str, dict[str, tuple[P.ActAsStep, ...]]] = {key: {} for key in sorted(seeds)}
    # Nodes already placed on a frontier. A node reached again from a longer
    # path is not re-expanded, so a function admitted only on that path is never
    # offered — conservative on dollars AND on the refusal reason, since a
    # refusal is published only once every admitted function has been tried.
    visited: set[str] = set(seeds)
    frontier = sorted(seeds)
    while frontier:
        nxt: list[str] = []
        for caller in frontier:
            entries = chains[caller]
            # Ruling 4 rule 2: the seized gate is spent at hop 1 and ONLY there,
            # so a seed is never constrained — not even by a hop some sibling
            # seed was witnessed making into it. Past hop 1 the plane is asked
            # the narrower question, and answers it over EVERY call site the
            # constraint admits rather than the first one it happens to hold.
            # ``frozenset(entries)``, never ``… or None``: an EMPTY admitted set
            # and hop 1 are different questions, and spelling them identically
            # would hand a non-seed node the unconstrained question — the via
            # rule gone and the seized gate spent a second time. Empty reaches
            # the plane as a constraint nothing satisfies and is refused under
            # ACT_AS_NO_CALL_SITE_UNDER_THE_ADMITTED_FUNCTION, which is what it
            # is. Only ``caller in seeds`` may produce the hop-1 question.
            admitted = None if caller in seeds else frozenset(entries)
            for hop in by_caller.get(caller, ()):
                for licensed in sorted(hop.licensed):
                    census["licensed_selectors"] += 1
                    verdict = act_as.acts_as(caller, hop.destination, licensed.selector, via=admitted)
                    if not verdict.witnessed or verdict.step is None:
                        refusals[verdict.outcome] += 1
                        continue
                    census["act_as_witnessed"] += 1
                    # The chain that admitted THIS step's own calling function.
                    # Indexed, not ``get``: ``via`` admitted the step only if
                    # its calling selector is one of these keys, so a miss is a
                    # broken invariant and must not publish a truncated chain.
                    prefix = () if caller in seeds else entries[verdict.step.calling_selector or ""]
                    chain = prefix + (verdict.step,)
                    # This licensed function of the destination is now one the
                    # principal can be made to enter it through, along this
                    # chain. First witnessed path wins, so the published chain
                    # is the shortest one the walk proved.
                    chains.setdefault(hop.destination, {}).setdefault(licensed.selector, chain)
                    if hop.destination not in visited:
                        visited.add(hop.destination)
                        nxt.append(hop.destination)
                    magnitude = magnitudes.get((hop.destination, licensed.selector))
                    if magnitude is None:
                        refusals["destination_carries_no_flow_out_magnitude_witness"] += 1
                        continue
                    census["destination_magnitude_witnessed"] += 1
                    key = value_plane.canonical(hop.destination)
                    sheet = value_plane.trimming_total(key)
                    # A sheet DETERMINED at $0 by delivery-shape disposition may
                    # not trim: the disposed assets are still held and delivery
                    # shape is not a claim about worth, so the sheet bounds what
                    # the entity holds and not what is there to move. Recorded
                    # rather than merged into "no sheet" — the entry publishes
                    # ``sheet_not_determined``, and that word would be false.
                    refused = (
                        SHEET_BOUND_REFUSED_BY_DISPOSITION
                        if sheet is None and value_plane.total(key) is not None
                        else None
                    )
                    # R4: the witness bounds the call, the sheet bounds what is
                    # there to move. Neither alone, and never their sum.
                    #
                    # And the sheet's COMPLETENESS is read here, with the sheet,
                    # rather than left for the entry to imply: a sheet that does
                    # not cover its node is a floor over what was priced, and a
                    # min against a floor hands back a smaller number than the
                    # witness on a bound nothing proved. Read for every sheet
                    # that exists, not only the ones that end up binding, so the
                    # entry can publish the direction whichever ceiling wins.
                    coverage = _asset_coverage(value_plane, key) if sheet is not None else None
                    complete = None if coverage is None else bool(coverage["complete"])
                    usd = min(magnitude.usd, sheet) if sheet is not None else magnitude.usd
                    # Every candidate is kept. Collapsing here on a running MAX
                    # would decide the selector, destination function, witness
                    # state and chain by whichever licensed selector the loop
                    # reached first whenever two of them tie on dollars, and
                    # would delete the losing candidate before that could be
                    # seen. The choice is made once, by a stated rule, below.
                    #
                    # The predicate lookup is keyed at the RAW destination and
                    # the licensed selector — the same pair the magnitude was
                    # read at — so the texts are the body of exactly the
                    # function this figure was read from.
                    candidates.setdefault(key, []).append(
                        _ComposedMagnitude(
                            entity=key,
                            selector=licensed.selector,
                            function=magnitude.function,
                            witness_state=magnitude.state,
                            witnessed_usd=magnitude.usd,
                            usd=usd,
                            sheet_usd=sheet,
                            sheet_bound_refused=refused,
                            sheet_is_proven_complete=complete,
                            sheet_bound_direction_basis=(
                                None
                                if coverage is None or complete is None
                                else _sheet_ceiling_direction_basis(coverage, complete)
                            ),
                            chain=chain,
                            predicates=conditions.predicates(hop.destination, licensed.selector),
                            # The destination witness's OWN execution, carried
                            # through unchanged. Composition joins an existing
                            # witness to a reach that was already proven; it
                            # observes nothing itself, so it has no execution of
                            # its own to name and must not invent one.
                            execution=magnitude.execution,
                        )
                    )
        frontier = sorted(nxt)
    # Hops the BFS never offered because it never reached their CALLER. Without
    # a name they leave the largest negative result on this corpus published as
    # silence: the two rows seized at a RolesAuthority carry eleven and three
    # licensed hops, offer nothing and refuse nothing, and a reader has no way
    # to tell that from a walk that found no licensed hop at all. Counted in the
    # same (hop, licensed function) units as every other refusal.
    for caller, hops_here in sorted(by_caller.items()):
        if caller in visited:
            continue
        for hop in hops_here:
            refusals[ACT_AS_CALLER_UNREACHED] += len(hop.licensed)
    selected = {key: _select_composed(pool) for key, pool in sorted(candidates.items())}
    census["composed_selected"] = len(selected)
    # The three-arm rule, on the SELECTED entries and never on the pool above.
    composed, withheld = _admit_composed(selected, principal_addresses=principal_addresses, planes=admission)
    census["composed"] = len(composed)
    census["composed_withheld"] = len(withheld)
    return composed, census, dict(sorted(refusals.items())), withheld


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
        return float(raw)  # type: ignore[arg-type]  # _is_number narrows it
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


# A licensed hop the composition walk never offered, because it never reached
# the hop's CALLER: every path from the seized node to it broke at an earlier
# hop that carried no act-as witness. Not an act-as refusal at this hop — the
# question was never asked here — and named separately for exactly that reason.
ACT_AS_CALLER_UNREACHED = "caller_not_reachable_from_the_seized_node"

HOP_REFUSED_SCOPE = "gate_scope_not_determined"
HOP_REFUSED_CONFERRAL = "gate_does_not_confer_this_scope"
HOP_REFUSED_CONDITION = "caller_condition_not_satisfiable"

# Every gate-control capability, each asking the conferral question with its own
# witness. The census has no signal instance to ask, so it asks the class-wide
# union — an upper bound on what any one instance's walk can confer, and labelled
# as one wherever it is published.
_CENSUS_GATE_CAPABILITIES = tuple(sorted(K.GATE_CONTROL_CAPABILITIES))

# Duplicate edge rows are real — 2,937 rows over 565 distinct pairs — and a pair
# is walked when ANY of its edges licenses it, so the census counts pairs and has
# to pick which of a pair's answers to report. Each ranking reports the answer
# that got FURTHEST, so a pair is never filed under a shortfall one of its own
# edges did not have. Ordering is by rank, ties impossible (the keys are total).
_CONFERRAL_RANK = {
    P.CONFERRAL_CONFERRED: 0,
    # The gate was asked and the label was readable; these two are the real
    # negative answers and rank alike.
    P.CONFERRAL_ROLE_NOT_LICENSED: 1,
    P.CONFERRAL_VARIABLE_NOT_REWRITTEN: 2,
    # Coverage shortfalls: nothing about this gate or this label was read.
    P.CONFERRAL_WRITES_NOT_EXTRACTED: 3,
    P.CONFERRAL_SCOPE_NOT_DETERMINED: 4,
}
# A pair every edge of which was bound reports the SHARPEST bound it hit: being
# disproved at the destination is a fact about the destination's own code, and
# outranks "this gate does not confer it", which outranks "the label said
# nothing".
_REFUSAL_RANK = {HOP_REFUSED_CONDITION: 0, HOP_REFUSED_CONFERRAL: 1, HOP_REFUSED_SCOPE: 2}
# Among the edges that DID walk a pair, the most specific scope reported it.
_SCOPE_KIND_RANK = {P.SCOPE_ROLES: 0, P.SCOPE_STATE_VAR: 1, P.SCOPE_NOT_DETERMINED: 2}


def _hop_census(closure: P.ControlClosure, conditions: P.ConditionPlane, conferral: P.ConferralPlane) -> dict[str, Any]:
    """Every hop in the graph, by what each class of capability can prove of it.

    Counted over DISTINCT ``(principal, anchor)`` pairs. ``control_graph_edges``
    holds one row per witnessed read — several times the pair count — so an
    edge-keyed census would report the same hop as many findings as the resolver
    happened to look.

    Published whether or not a bound ever bit: a rule with no fired count and a
    rule that was never wired read identically from the outside.

    Gate control is now capability-dependent — ownership.transfer and
    authority.replace confer different hops — so the class-level block is the
    UNION over the five gate capabilities (a hop is counted walked there if ANY
    of them confers it) and ``by_capability`` carries each one's own answer. The
    union is an upper bound twice over: over the capabilities, and over the
    instances, because each capability is asked with the union of what its
    witnesses rewrite anywhere rather than with one function's own set.
    """
    pairs: dict[tuple[str, str], list[P.ControlEdge]] = defaultdict(list)
    for edge in closure.edges:
        pairs[(edge.principal, edge.anchor)].append(edge)
    census: dict[str, Any] = {"distinct_hops": len(pairs), "edges": len(closure.edges)}

    def count(grant: P.GateGrant | None) -> dict[str, Any]:
        counts: dict[str, int] = {"walked": 0, HOP_REFUSED_SCOPE: 0, HOP_REFUSED_CONFERRAL: 0, HOP_REFUSED_CONDITION: 0}
        counts.update(dict.fromkeys(P.WALKED_COVERAGE, 0))
        by_scope_kind = {P.SCOPE_ROLES: 0, P.SCOPE_STATE_VAR: 0, P.SCOPE_NOT_DETERMINED: 0}
        conferral_outcomes: dict[str, int] = dict.fromkeys(P.CONFERRAL_OUTCOMES, 0)
        for (principal, anchor), edges in pairs.items():
            if grant is not None:
                outcomes = [grant.confers(edge.scope, edge.anchor).outcome for edge in edges]
                conferral_outcomes[min(outcomes, key=lambda o: _CONFERRAL_RANK[o])] += 1
            bounds = [(_hop_bound(edge, conditions, grant=grant), edge) for edge in edges]
            walked = [edge for bound, edge in bounds if bound is None]
            if not walked:
                refusals = [str(bound["reason"]) for bound, _ in bounds if bound is not None]
                counts[min(refusals, key=lambda r: _REFUSAL_RANK[r])] += 1
                continue
            counts["walked"] += 1
            by_scope_kind[min((edge.scope.kind for edge in walked), key=lambda k: _SCOPE_KIND_RANK[k])] += 1
            counts[conditions.hop(principal, anchor).coverage or P.WALKED_NO_FUNCTION] += 1
        out: dict[str, Any] = dict(counts)
        out["walked_by_scope_kind"] = dict(sorted(by_scope_kind.items()))
        if grant is not None:
            out["conferral"] = dict(sorted(conferral_outcomes.items()))
        return out

    census["code_control"] = count(None)
    by_capability: dict[str, Any] = {}
    walked_by_any: set[tuple[str, str]] = set()
    conferred_by_any: set[tuple[str, str]] = set()
    for capability in _CENSUS_GATE_CAPABILITIES:
        grant = conferral.capability_grant(capability)
        by_capability[capability] = count(grant)
        for pair, edges in pairs.items():
            for edge in edges:
                if grant.confers(edge.scope, edge.anchor).conferred:
                    conferred_by_any.add(pair)
                    if _hop_bound(edge, conditions, grant=grant) is None:
                        walked_by_any.add(pair)
    census["gate_control"] = {
        "walked_by_at_least_one_gate_capability": len(walked_by_any),
        "conferred_by_at_least_one_gate_capability": len(conferred_by_any),
        "conferred_by_none": len(pairs) - len(conferred_by_any),
        "reading": (
            # "and no finding walks it" was here: a universal over the findings
            # population, authored in a census that runs over the control
            # closure BEFORE any finding exists and therefore never asked it.
            # What is stated instead is the property this function does
            # establish — why the union over-counts — which holds at every value
            # of the counters.
            "the union over the five gate capabilities, each asked with the class-wide union of "
            "what its witnesses rewrite. It is an upper bound on every real walk twice over — "
            "over capabilities, because a pair walked by any one of the five is counted here, "
            "and over instances, because each capability is asked with the union of what its "
            "witnesses rewrite anywhere rather than with one instance's own set. Nothing here "
            "counts findings, and no row is claimed to walk this width. by_capability is "
            "the per-capability answer at the same class-wide width"
        ),
    }
    census["gate_control_by_capability"] = by_capability
    # The label-names-nothing population, counted three ways because a pair is
    # not an edge and a pair carrying one unlabelled edge is not a pair a gate
    # can be withheld on: the walk reaches a destination if ANY of the pair's
    # edges confers it, so only pairs with no labelled edge at all can lose their
    # hop to this rule. Publishing only the deduped number would report the 55
    # unlabelled role edges as 9.
    unlabelled_edges = [edge for edge in closure.edges if not edge.scope.is_determined]
    unlabelled_pairs = {(edge.principal, edge.anchor) for edge in unlabelled_edges}
    by_relation: dict[str, int] = defaultdict(int)
    for edge in unlabelled_edges:
        by_relation[str(edge.relation) if edge.relation else edge.witness] += 1
    census["scope_not_determined"] = {
        "edges": len(unlabelled_edges),
        "pairs_carrying_one": len(unlabelled_pairs),
        "pairs_with_no_labelled_edge": sum(
            1 for pair in unlabelled_pairs if all(not edge.scope.is_determined for edge in pairs[pair])
        ),
        "edges_by_relation": dict(sorted(by_relation.items())),
        "reading": (
            "edges whose label names neither a role nor a state variable — the role_principal "
            "rows that restate their own relation, and the column witnesses that carry no label "
            "at all. Every one is published as not_determined for gate control and none is "
            "dropped; code control does not ask the question"
        ),
    }
    census["reading"] = (
        "what each class could establish about every hop the closure holds, before any "
        "signal seeds it. A hop counted not_determined here is withheld from a finding "
        "only when that finding's walk actually needs it and no other path reaches the "
        "destination; the per-finding lists carry that narrower population. The four "
        "walked_* counts partition `walked` by what was READ to walk it: only "
        "walked_on_fully_analysed_conditions rests on a surface read in full, "
        "walked_on_partly_analysed_conditions found no guard on the functions it could read "
        "and could not read all of them, and the last two are hops where no condition "
        "existed to read at all, walked on the edge alone. walked_by_scope_kind partitions "
        "the same total by what the edge label named. `conferral` partitions every hop by "
        "the CONFERRAL test — whether the gate is witnessed to seize the authority the hop "
        "runs on — which replaced the label-presence test that walked any labelled edge"
    )
    return census


def _hop_bound(
    edge: P.ControlEdge, conditions: P.ConditionPlane, *, grant: P.GateGrant | None
) -> dict[str, Any] | None:
    """Why this hop is NOT walked as proven, or ``None`` when it is.

    Two bounds, in the order that costs least to decide. The SCOPE bound is
    gate-control's alone — ``grant`` is the gate asking, and ``None`` is code
    control, which does not ask: controlling the code exercises everything the
    code is authorized to exercise, whatever the label happened to record.

    For a gate the question is CONFERRAL, not label presence: a ``roles N`` edge
    is walked where the role -> selector join names functions role N licenses at
    the destination, and a ``state_var`` edge where the gate's own witness is
    observed to rewrite a variable of that name. A label naming a scope the gate
    is not witnessed to seize (`hook`, `vault`, `roleRegistry`) is no longer
    enough, and neither is a label naming nothing at all — 55 of the role edges
    restate their own relation and name no role.

    The CONDITION bound is shared: the destination's own guards may pin their
    caller to the destination itself, and no authority relation makes one
    address another.

    A refused hop is a published ``not_determined``, never a silent drop and
    never a proven negative.
    """
    if grant is not None:
        verdict = grant.confers(edge.scope, edge.anchor)
        if not verdict.conferred:
            return {
                "caller": edge.principal,
                "destination": edge.anchor,
                # The unlabelled edges keep their own reason: "the label named
                # nothing" and "the label named something this gate does not
                # seize" are different shortfalls and only the first is a
                # pipeline gap.
                "reason": (
                    HOP_REFUSED_SCOPE if verdict.outcome == P.CONFERRAL_SCOPE_NOT_DETERMINED else HOP_REFUSED_CONFERRAL
                ),
                "conferral": verdict.outcome,
                "capability": grant.capability,
                "relation": edge.relation,
                "witness": edge.witness,
                "edge_label": edge.scope.label,
                "basis": verdict.basis,
            }
    hop = conditions.hop(edge.principal, edge.anchor)
    if hop.state == P.HOP_WALKED:
        return None
    return {
        "caller": edge.principal,
        "destination": edge.anchor,
        "reason": HOP_REFUSED_CONDITION,
        "relation": edge.relation,
        "witness": edge.witness,
        "edge_label": edge.scope.label,
        "basis": hop.basis,
        "surface": hop.surface,
        "functions_consulted": hop.functions_consulted,
        "disproving_conditions": list(hop.disproving),
    }


def _behind_the_frontier(
    gaps: list[dict[str, Any]],
    closure: P.ControlClosure,
    conditions: P.ConditionPlane,
    value_plane: P.ValuePlane,
    reached: set[str],
) -> dict[str, Any]:
    """The entities a row's withheld hops hide, counted rather than left implicit.

    A hop published as ``not_determined`` names one destination. The closure
    places a whole subtree behind that destination, and none of it appears on the
    row: two published hops can withhold twenty-two entities, twenty of which are
    named nowhere in the document. The withheld population is therefore SIZED
    here, by walking the closure from the withheld destinations with no scope
    bound at all — the widest walk this fold performs, which is code control's —
    and subtracting what the row reached anyway.

    This is the size of what was withheld and NOT a claim of reach: the row does
    not reach these entities, that is the whole point. The number is an upper
    bound on the subtree for the same reason the code-control walk is an upper
    bound on any gate's, and it is published as one.
    """
    if not gaps:
        return {"hops": 0, "entities": 0, "entity_keys": [], "reading": "no hop was withheld"}
    frontier = {str(gap["destination"]) for gap in gaps}
    seen, _, _, _ = _closure(frontier, closure, conditions, grant=None)
    behind = sorted({value_plane.canonical(key) for key in seen} - reached)
    return {
        "hops": len(gaps),
        "entities": len(behind),
        "entity_keys": behind,
        "reading": (
            "entities the closure places behind the hops this row could not establish, and which "
            "the row therefore does NOT reach. Sized by walking from the withheld destinations "
            "with no scope bound — the widest walk this fold performs — so it is an upper bound "
            "on the withheld subtree, published because a withheld frontier hop otherwise hides "
            "everything behind it with no trace in the document"
        ),
    }


def _closure(
    seeds: set[str], closure: P.ControlClosure, conditions: P.ConditionPlane, *, grant: P.GateGrant | None
) -> tuple[set[str], list[dict[str, Any]], dict[str, set[P.LicensedFunction]], list[_WalkedHop]]:
    """The reach the walk proves, every hop it could not establish, and what the
    hops it did walk LICENSE at each destination.

    ``grant`` is the gate doing the walking; ``None`` is code control, which asks
    no conferral question. The third return value is the role -> selector join's
    output, keyed by the RAW anchor: the named functions a walked ``roles`` hop
    licenses there. Callers that publish it re-key onto the canonical entity,
    which is what the reach set is keyed on and what a consumer joins against.
    It is the reach's own answer to "to do *what*", and it is
    what a compositional magnitude is later attributed to — a destination reached
    only through state-variable hops has no entry, because nothing named which of
    its functions the gate reaches.

    The burn sentinel is refused at every hop. ``load_control_closure`` already
    refuses ``0x0`` at both ends of an edge, so on the production path that guard
    never fires. It is here because the fold's guarantee must not be a property
    of how the closure was BUILT: the sentinel is the single largest fan-out in
    the graph, and one edge into it — from a repoint witness, a hand-built
    closure, or a future loader — would otherwise hand a row everything behind
    ``msg.sender != 0x0``. Refusing reach is always monotone, so the second line
    of defence costs nothing.

    The second return value is the hops this walk did not walk AS PROVEN, keyed
    on the distinct ``(caller, destination)`` pair. The edge table carries one
    row per witnessed read — 2,937 rows over 565 pairs on the reference corpus —
    so counting refusals per EDGE would report the same withheld hop five times
    and read as five findings.

    The fourth return value is the walked hops themselves — (caller, destination,
    what that hop licensed there). The licensed map above collapses every caller
    that reached a destination into one entry, which is the right shape for "what
    does this row reach it to do" and the wrong one for composing a magnitude:
    the question a composition asks is whether THAT caller can be made to act,
    and a map keyed on the destination alone cannot say which caller a licence
    came from.
    """
    seen: set[str] = set()
    withheld: dict[tuple[str, str], dict[str, Any]] = {}
    licensed: dict[str, set[P.LicensedFunction]] = defaultdict(set)
    walked: dict[tuple[str, str], set[P.LicensedFunction]] = {}
    stack = [key for key in sorted(seeds) if not P.is_zero_key(key)]
    while stack:
        key = stack.pop()
        if key in seen:
            continue
        seen.add(key)
        for edge in closure.edges_from(key):
            if P.is_zero_key(edge.anchor):
                continue
            bound = _hop_bound(edge, conditions, grant=grant)
            if bound is None:
                here: set[P.LicensedFunction] = set()
                if grant is not None:
                    here = set(grant.confers(edge.scope, edge.anchor).licensed)
                    licensed[edge.anchor].update(here)
                walked.setdefault((edge.principal, edge.anchor), set()).update(here)
                if edge.anchor not in seen:
                    stack.append(edge.anchor)
                continue
            withheld.setdefault((edge.principal, edge.anchor), bound)
    # A hop another path reached anyway withheld nothing: the destination is in
    # reach either way, and reporting it as a gap would publish a shortfall the
    # walk does not have.
    gaps = [bound for pair, bound in sorted(withheld.items()) if pair[1] not in seen]
    hops = [
        _WalkedHop(caller=pair[0], destination=pair[1], licensed=frozenset(rows))
        for pair, rows in sorted(walked.items())
    ]
    return seen, gaps, {key: set(rows) for key, rows in sorted(licensed.items()) if rows}, hops


def _gap_reading(
    exposure: float | None,
    unpriced: list[Any],
    exhausted: list[Any],
    partial: list[Any],
    ceilings_excluded: list[Any],
) -> str:
    """How to read one gap entry, assembled from the reasons that actually fired.

    A null exposure and a published one are opposite cases and cannot share a
    sentence: the first measured nothing, the second measured a MARGINAL share
    and understates by an amount this accounting can name.
    """
    parts = [
        (
            "not counted and not read as zero; where the exposure is null nothing "
            "about this finding's dollar exposure was measured"
        )
        if exposure is None
        else (
            "the published figure is this row's MARGINAL share of what it reaches, so it is "
            "a floor on this finding's exposure and not a measurement of it"
        )
    ]
    if unpriced:
        parts.append(
            "the unpriced entities are absent from it rather than counted as zero, so nothing "
            "here says they hold nothing"
        )
    if exhausted:
        parts.append(
            "the entities under budget_exhausted_entities were charged in full by the findings "
            "listed against them, so this row's share of those entities is unmeasured, not zero"
        )
    if partial:
        parts.append(
            "the entities under budget_partially_exhausted_entities were charged at less than "
            "this row's own fraction, and the difference is missing from the figure"
        )
    if ceilings_excluded:
        parts.append(
            "the entities under ceiling_entities_excluded_from_exposure are priced from their own "
            "SHEET CEILING and are deliberately outside this numerator: what is proven there is an "
            "at-most on a move nobody witnessed, which is not expected loss, and it spends none of "
            "their exposure budget either — so their dollars are absent from the figure by rule "
            "and not by a lookup that failed"
        )
    return "; ".join(parts)


def _grade(
    findings: list[dict[str, Any]], value_plane: P.ValuePlane
) -> tuple[float | None, float | None, float | None, list[dict[str, Any]], dict[str, Any]]:
    if not findings:
        return None, None, None, [], _exposure_coverage([], value_plane, value_plane.tracked_total)
    for index, finding in enumerate(findings):
        finding["net_points_lambda"] = round(finding["raw_points"] * (K.LAMBDA**index), 4)
    cumulative = round(sum(f["net_points_lambda"] for f in findings), 4)
    grade_lambda = round(100.0 - min(cumulative, 100.0), 4)

    claimed: dict[str, float] = defaultdict(float)
    # Which findings spent each entity's budget, so a later row that finds it
    # empty can name them instead of publishing the emptiness as a measurement.
    claimed_by: dict[str, list[dict[str, Any]]] = defaultdict(list)
    exposure = 0.0
    gaps: list[dict[str, Any]] = []
    any_priced = False
    for finding in findings:
        # W2c/R9 hook (this dict lookup is the whole change to this function):
        # inv.5 is the weakest path TO THAT ENTITY, so a merged unit charges each
        # entity at the rung of the members proven to reach it, not at the unit's
        # weakest member.
        per_entity_weakness = finding.get("weakness_by_entity") or {}
        mine = 0.0
        # Entities this row could actually measure a share of. An entity whose
        # budget earlier rows already spent is priced and still unmeasurable,
        # so counting it here is what published the exhaustion as a zero.
        measured_entities = 0
        exhausted: list[dict[str, Any]] = []
        partial: list[dict[str, Any]] = []
        unpriced: list[str] = []
        exclusive = finding.get("subsumed_exclusive_value_by_entity") or {}
        charged_entities = list(finding["reach_entities"]) + [
            k for k in exclusive if k not in finding["reach_entities"]
        ]
        # §6.4: a SHEET ceiling stays out of the exposure numerator entirely. It
        # is a risk-weighted upper bound on a move nobody witnessed, and charging
        # it here would do two things at once — inflate exposure_usd off bounds,
        # and SPEND that entity's budget, which silently displaces a later row
        # that measured a real extraction at the same entity down to its
        # marginal share.
        #
        # The set is the SHEET half only. A composed extraction ceiling is a
        # destination function's own witnessed flow, charges the budget today,
        # and keeps charging: the two are published apart precisely so this loop
        # can tell them apart.
        sheet_ceilings = set(finding.get("entities_priced_from_a_sheet_ceiling") or [])
        exclusive_ceilings = set(finding.get("subsumed_exclusive_sheet_ceiling_entities") or [])
        ceilings_excluded: list[str] = []
        for key in charged_entities:
            # The row's OWN per-entity contribution, not its total: charging the
            # row total against each entity would multiply one witnessed
            # magnitude by the number of entities it was spread across.
            held = finding["value_by_entity"].get(key)
            # An entity only a subsumed row reaches is charged at THAT row's
            # fraction, never at this one's.
            key_fraction = finding["severity_proven"] * per_entity_weakness.get(key, finding["weakness"])
            excluded = False
            if key in sheet_ceilings:
                # §6.4: this row's own figure here is a proven upper bound on a
                # move nobody witnessed. It charges nothing — which is not the
                # same as the entity being unmeasurable, so the fall-through to a
                # subsumed row's WITNESSED figure below still runs.
                held = None
                excluded = True
            if held is None and key in exclusive:
                if key in exclusive_ceilings:
                    # The exclusive figure is itself a sheet ceiling, published by
                    # a subsumed row. The skip is about the FIGURE, so it applies
                    # wherever the figure came from: the top row's ceiling list
                    # does not name this key, and reading only that list is how a
                    # ceiling charges a budget its own row's copy is exempt from.
                    excluded = True
                else:
                    held = exclusive[key]["usd"]
                    key_fraction = exclusive[key]["fraction"]
                    # A real measurement is charged after all. The row's own
                    # ceiling here was skipped and nothing was lost by it, so
                    # there is nothing to disclose as excluded at this key.
                    excluded = False
            if held is None:
                if excluded:
                    # Named, not silently skipped. A row whose every priced entity
                    # is a sheet ceiling publishes exposure_usd null, and a null
                    # with no stated reason is indistinguishable from one nobody
                    # could price.
                    ceilings_excluded.append(key)
                    continue
                # An unpriced entity contributes nothing AND is disclosed. Reading
                # it as $0.00 publishes "this capability exposes nothing" out of a
                # price lookup that never answered.
                unpriced.append(key)
                continue
            room = max(0.0, 1.0 - claimed[key])
            if room <= 0.0:
                # Earlier findings spent this entity's whole budget. The
                # remainder is not a measured $0.00 — it is a share this
                # accounting cannot separate from theirs, so it is disclosed
                # with the rows that took it rather than summed as a zero.
                exhausted.append({"entity": key, "claimed_by": list(claimed_by[key])})
                continue
            measured_entities += 1
            take = min(key_fraction, room)
            if room < key_fraction:
                # A partial charge understates by exactly the difference, and it
                # does so silently: the published figure is this row's MARGINAL
                # share, not its exposure to the entity. Which row was marginal
                # is a function of the sort order, not of what anyone reaches.
                partial.append(
                    {
                        "entity": key,
                        "fraction_wanted": round(key_fraction, 6),
                        "fraction_taken": round(take, 6),
                        "claimed_by": list(claimed_by[key]),
                    }
                )
            if take > 0:
                claimed[key] += take
                claimed_by[key].append(
                    {
                        "principal_unit": finding["principal_unit"],
                        "capability": finding["capability"],
                        "fraction_taken": round(take, 6),
                    }
                )
                mine += take * held
        # The keys a ceiling left contributing nothing are not "charged", and the
        # set is the loop's own answer rather than the two ceiling lists re-read:
        # a key whose ceiling was skipped and whose witnessed exclusive figure
        # was then charged belongs here, and no re-derivation off the lists can
        # tell that case from a key that charged nothing.
        ceiling_only = set(ceilings_excluded)
        finding["exposure_entities_charged"] = sorted(
            key
            for key in charged_entities
            if key not in ceiling_only and (finding["value_by_entity"].get(key) is not None or key in exclusive)
        )
        if measured_entities:
            any_priced = True
            finding["exposure_usd"] = round(mine, 2)
        else:
            # Either no priced entity in reach, or every priced one's budget was
            # already spent: the exposure of this finding is a quantity nobody
            # measured, and null is the only honest answer.
            finding["exposure_usd"] = None
        if unpriced or exhausted or partial or ceilings_excluded or finding["exposure_usd"] is None:
            # One gap per finding, never two: a row with an unpriced entity AND
            # a spent budget has one set of reasons, not one entry per reason.
            # Every key is present on every entry — an empty list is the proven
            # negative "this did not happen", which is not the same published
            # fact as a key that is missing.
            #
            # S5: repopulated from the row's own undetermined instances, which
            # is where an unpriced entity actually lands.
            unpriced_entities = sorted(set(unpriced) | {row["entity"] for row in finding["undetermined_instances"]})
            gaps.append(
                {
                    "principal_unit": finding["principal_unit"],
                    "capability": finding["capability"],
                    "unpriced_entities": unpriced_entities,
                    "undetermined_instances": finding["undetermined_instances"],
                    "budget_exhausted_entities": exhausted,
                    "budget_partially_exhausted_entities": partial,
                    # Present on every entry, empty where it did not happen: an
                    # absent key would read as a question nobody asked.
                    "ceiling_entities_excluded_from_exposure": sorted(ceilings_excluded),
                    "exposure_usd": finding["exposure_usd"],
                    "reading": _gap_reading(
                        finding["exposure_usd"], unpriced_entities, exhausted, partial, ceilings_excluded
                    ),
                }
            )
        # A finding whose exposure is not_determined contributes nothing to the
        # total and is disclosed in exposure_gaps; it is never summed as a zero.
        if finding["exposure_usd"] is not None:
            exposure += finding["exposure_usd"]

    tracked = value_plane.tracked_total
    coverage = _exposure_coverage(findings, value_plane, tracked)
    if not tracked or not any_priced:
        return grade_lambda, None, round(exposure, 2), gaps, coverage
    return grade_lambda, round(100.0 * (1.0 - exposure / tracked), 3), round(exposure, 2), gaps, coverage


def _exposure_coverage(findings: list[dict[str, Any]], value_plane: P.ValuePlane, tracked: float) -> dict[str, Any]:
    """How much of the perimeter the exposure ratio was actually measured over.

    ``grade_exposure`` is ``100 * (1 - exposure / tracked_total)``. The
    denominator is the whole priced perimeter; the numerator is a sum over only
    the findings whose exposure could be measured at all. Once an unwitnessed
    magnitude publishes ``not_determined`` instead of a balance sheet, most
    findings contribute nothing to that numerator — and a ratio near 100 then
    reads as "almost nothing is exposed" when what it says is "almost nothing
    was measurable". The ratio is not adjusted for this: adjusting it would mint
    a number out of the same absence. It is DISCLOSED, so the figure cannot be
    read as a measurement it is not.

    ``perimeter_usd_charged`` is the priced value of the entities that received
    a charge, and ``perimeter_usd_reached_unmeasured`` the priced value reached
    by findings whose own exposure is ``not_determined`` and which no charged
    row covers — the weight the ratio is silent about.
    """
    determined = [f for f in findings if f.get("exposure_usd") is not None]
    undetermined = [f for f in findings if f.get("exposure_usd") is None]
    charged: set[str] = set()
    for finding in determined:
        charged.update(finding.get("exposure_entities_charged") or [])

    def priced(keys: set[str]) -> float:
        total = 0.0
        for key in sorted(keys):
            value = value_plane.total(value_plane.canonical(key))
            if value is not None:
                total += value
        return round(total, 2)

    unmeasured: set[str] = set()
    for finding in undetermined:
        unmeasured.update(value_plane.canonical(key) for key in finding.get("reach_entities") or [])
    unmeasured -= {value_plane.canonical(key) for key in charged}
    charged_usd = priced(charged)
    return {
        "findings": len(findings),
        "findings_with_determined_exposure": len(determined),
        "findings_with_exposure_not_determined": len(undetermined),
        "entities_charged": len(charged),
        "perimeter_usd_charged": charged_usd,
        "perimeter_usd_reached_unmeasured": priced(unmeasured),
        "tracked_total_usd": round(tracked, 2) if tracked else None,
        "tracked_share_measured_pct": (round(100.0 * charged_usd / tracked, 3) if tracked else None),
        "reading": (
            "grade_exposure divides a numerator summed over "
            f"{len(determined)} of {len(findings)} findings by the WHOLE priced perimeter. The "
            "other findings publish exposure_usd null — no witness proved how much their reach "
            "moves — and contribute nothing rather than a zero, so a grade_exposure near 100 is "
            "'this much of the perimeter was not measured against', never 'this much is safe'. "
            "perimeter_usd_reached_unmeasured is the priced value those findings reach that no "
            "charged row covers"
        ),
    }


def _entities_outside_perimeter(
    signals: list[FunctionSignal],
    answered: dict[str, list[int]],
    perimeter: dict[str, float],
    value_plane: P.ValuePlane,
) -> list[str]:
    """Deployment AND reach keys the confidence denominator never asked about.

    A signal answers questions about the entity it was distilled on, and it
    charges value against the entities it REACHES. Checking only the first left
    a reach key that no denominator accounts for invisible to the disclosure
    that exists to name it — value carried into a finding by an entity whose
    unanswered weight is nowhere. The keys the closure walk ADDS to a reach are
    admitted to the perimeter by construction (every principal and everything it
    controls), so the witnessed keys are the ones that can fall outside. The zero
    address is refused by an admission rule with its own published count, so its
    absence is a decision rather than a gap and it is not reported here.
    """
    outside = {key for key in answered if key not in perimeter}
    for signal in signals:
        for raw in signal.value_entity_keys:
            key = value_plane.canonical(raw)
            if key not in perimeter and not P.is_zero_key(key):
                outside.add(key)
    return sorted(outside)


# The three ways the reach-magnitude term counts a signal as ANSWERED, as
# tokens, so the reading below is assembled from the same names the loop counts
# under. Each clause states which evidence supplied the answer, because that is
# the fact a consumer subtracting one class from the term needs: they are three
# different proofs of three different strengths and one word for all of them
# ("witnessed") is what made the split necessary in the first place.
CREDIT_PATH_OWN = "own_call_witness"
CREDIT_PATH_COMPOSED = "composed_destination_witness"
CREDIT_PATH_SHEET_CEILING = "sheet_ceiling"

_CREDIT_PATH_CLAUSES = {
    CREDIT_PATH_OWN: "a witness on the signal's OWN call, which measures what that call moves",
    CREDIT_PATH_COMPOSED: (
        "the DESTINATION function's own flow.out witness, COMPOSED along a path every hop of "
        "which carries an act-as witness — the same kind of answer reached through one more "
        "join, itemised per row under reach_composed_magnitudes"
    ),
    CREDIT_PATH_SHEET_CEILING: (
        "the controlled node's own priced SHEET, which bounds the move from ABOVE and never "
        "measures it: replacing that node's code leaves none of that node's code between the "
        "principal and what it holds, so at-most-what-is-there is proven without a call being "
        "witnessed at all, itemised per row under reach_sheet_ceiling_magnitudes"
    ),
}


def _credit_path_reading(counts: dict[str, int]) -> str:
    """How the answered population splits across the three credit paths.

    Every registered path is named whatever it counted, including zero. A clause
    dropped for having no carriers would leave a reader unable to tell a path
    that did not fire on this corpus from one this model does not have, and the
    counts are the whole point of publishing the split.
    """
    parts = [f"{counts.get(path, 0)} from {clause}" for path, clause in _CREDIT_PATH_CLAUSES.items()]
    return (
        "an answer counts here from any of THREE witnesses, and the population splits "
        + "; ".join(parts)
        + ". They are not equally strong and are counted apart so a consumer can subtract "
        "whichever of them it does not want to credit"
    )


def _mixed_witness_cause(mixed: int, composed: int, ceiling: int, fold_only: int) -> str:
    """What put entities in the mixed population, counted rather than asserted.

    An answer the FOLD supplied is what turns a 0/n entity into a mixed one, and
    there are now two of those. The sentence names the counts of each because
    naming only the mechanism would keep reading as though both fired on a corpus
    where one of them has no carriers. The empty case is an earned negative: the
    edge exists on its own, from entities that carry a call witness of their own
    at some signals and not at others, and saying so is a different fact from
    saying nothing.
    """
    if not mixed:
        return (
            "No entity is in this population, so the edge has no carriers here — a measured "
            "zero and not an absence of the shape"
        )
    if not composed and not ceiling:
        return (
            f"None of the {mixed} entity(ies) here was put in this population by an answer the "
            "FOLD supplied: every one of them carries a witness on some of its own calls and "
            "none on others, which is the edge in its plainest form"
        )
    return (
        f"Of the {mixed} entity(ies) here, {composed} carry a COMPOSED destination witness and "
        f"{ceiling} a SHEET CEILING — answers the fold supplied rather than the signal — and "
        f"{fold_only} of them carry no call witness of their own at all, so for those the "
        "fold's own answer is the only thing that moved them off 0/n and is what put them in "
        "this population"
    )


def _confidence(
    signals: list[FunctionSignal],
    value_plane: P.ValuePlane,
    closure: P.ControlClosure,
    proven_eoas: set[str],
    discovery_entities: dict[str, set[str]] | None = None,
    composed_signals: set[tuple[Any, ...]] | None = None,
    ceiling_signals: set[tuple[Any, ...]] | None = None,
) -> dict[str, Any]:
    """Monotone in resolution work: the denominator is the PERIMETER.

    The perimeter's base population is the protocol's ``contracts`` rows, unioned
    with the value plane and the control closure. Discovery fixes that base, so it
    does not move with what has been analysed — losing a contract's signals cannot
    drop its unanswered weight out of its own denominator — while an unpriced
    contract outside the closure still carries ``band(None)`` of unanswered
    weight rather than vanishing. Seeding it from the signal population instead
    is what let LESS analysis publish MORE confidence. Four figures, and the
    headline is the MINIMUM — knowing who can call something, knowing what it
    does, being able to price what it reaches, and knowing HOW MUCH the reach
    moves are different questions.

    The closure the scorer WALKS is a subset of the relations discovery proved
    exist, so seeding the perimeter from the walked closure alone let declining a
    relation FREE confidence: the entities that relation proved are principals of
    gated functions never entered the denominator. ``discovery_entities`` carries
    every endpoint of every relation in the DB's own authority vocabulary, walked
    or not, so declining one charges confidence and can never relieve it (inv. 6).

    The fourth term is the honest home for an unproven magnitude. A signal that
    proved reach but not how much value that reach moves is UNANSWERED here — the
    unknown that otherwise has nowhere to land but the grade. Its denominator is
    the whole perimeter, exactly as the reachability and capability terms', which
    is the only shape monotone under losing work: an entity whose signals vanish
    contributes zero either way, while a denominator scoped to entities that
    happen to carry a signal would RISE when a signal is lost.

    ``ceiling_signals`` is the fold's OTHER answer to the magnitude question and
    the THIRD credit path: the signals whose controlled node was priced from its
    own SHEET. It is consumed exactly as the fold built it and is never
    re-derived here — a second derivation of "which signals got an answer" is
    precisely what drifts from the rows that publish one.

    What that population IS matters as much as that it is credited. It is
    per-entity and STANDING: the signals whose sheet ceiling is the figure the
    row actually publishes at that entity. A ceiling a larger contribution
    displaced is not in it, and neither is one the per-key sheet reconciliation
    withdrew, so every credited answer has a carrier in the published document
    rather than a number the fold computed and then discarded. Ties keep their
    credit — several calls on one node read the same sheet and each of them
    proved the figure the row publishes — and only a ceiling strictly beaten
    loses it.

    Every key is admitted through ``value_plane.canonical``: an implementation
    is the same entity as the proxy that deploys it, and admitting both hands
    the impl a second copy of the proxy's value band that no signal can ever
    answer (signals are distilled at the proxy address). The alias map comes
    from the same discovery-fixed ``contracts`` rows as the base population, so
    folding through it keeps the denominator independent of analysis. The zero
    address is excluded outright — it is a burn sentinel, not an assessable
    entity (``msg.sender != 0x0``). A perimeter entity proven codeless
    (``resolved_type == 'eoa'``, earned from an empty ``eth_getCode``) has no
    capability surface to leave unanswered: its reach and capability terms are
    vacuously answered, while its pricing term is untouched — holding value is
    a question code-lessness does not answer.
    """
    perimeter: dict[str, float] = {}
    folded: set[str] = set()
    zero_excluded: set[str] = set()

    def admit(raw: str) -> None:
        if P.is_zero_key(raw):
            zero_excluded.add(raw)
            return
        key = value_plane.canonical(raw)
        if key != raw:
            folded.add(raw)
        perimeter.setdefault(key, K.band(value_plane.total(key)))

    for key in sorted(value_plane.contract_entities):
        admit(key)
    for key in sorted(value_plane.per_asset):
        admit(key)
    for key in closure.principals():
        admit(key)
        for controlled in closure.controlled_by(key):
            admit(controlled)
    # Everything above is what the scorer WALKED. Everything below is what
    # discovery PROVED exists, per relation — counted against the walked base so
    # each relation's own contribution is visible rather than assigned to
    # whichever relation happened to be admitted first.
    walked = set(perimeter)
    discovery = discovery_entities or {}
    discovery_admitted: dict[str, int] = {}
    for relation in sorted(discovery):
        keys = sorted(discovery[relation])
        for key in keys:
            admit(key)
        discovery_admitted[relation] = len(
            {value_plane.canonical(key) for key in keys if not P.is_zero_key(key)} - walked
        )
    denominator = round(sum(sorted(perimeter.values())), 6)

    reach: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    scored: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    priced: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    magnitude: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    magnitude_census: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    composed_census: dict[str, int] = defaultdict(int)
    ceiling_census: dict[str, int] = defaultdict(int)
    # Counted rather than subtracted. The three credit paths are exclusive by the
    # order they are tried below, and a count taken directly cannot report a
    # population that an arithmetic residual would silently absorb if that ever
    # stopped being true.
    own_witness_signals = 0
    # Which of the three paths answered at each entity, so the mixed-entity
    # reading below can say what put an entity in that population instead of
    # asserting a cause. Kept per key because "mixed" is a per-entity fact.
    credit_paths_by_key: dict[str, set[str]] = defaultdict(set)
    for signal in signals:
        key = value_plane.canonical(entity_key(signal.chain, signal.deployment_address))
        answered = (
            signal.authority_openness == OPENNESS_OPEN
            or signal.principal_state == PRINCIPAL_STATE_ENUMERATED
            or _gate(signal, "exact_empty_credit").is_determined
        )
        reach[key][1] += 1
        scored[key][1] += 1
        if answered:
            reach[key][0] += 1
        if answered and signal.enters_grade:
            scored[key][0] += 1
        if signal.claim_id == "flow.out":
            # The pricing term: an unpriceable reach is a real gap in what the
            # grade could measure, and leaving it out of confidence would make
            # unpriceable value free.
            priced[key][1] += 1
            asset_class = _gate(signal, "asset_class")
            decidable = not _gate(signal, "token_identity").is_determined and (
                not asset_class.is_determined
                or asset_class.value not in SINGLE_ASSET_CLASSES
                or _gate(signal, "asset_identity").is_determined
            )
            if decidable and value_plane.total(key) is not None:
                priced[key][0] += 1
        if signal.value_state == VALUE_STATE_PROVEN_REACH:
            # The reach-magnitude term. A proven reach whose magnitude has no
            # witness is the unknown that otherwise lands in the grade as the
            # entity's whole balance sheet; here it lands as UNANSWERED, which is
            # the only place it can sit without being published as a number.
            #
            # EVERY proven-reach signal is in the denominator. A per-capability
            # exclusion list was tried and removed: a capability that publishes
            # proven_reach is claiming it can move value, and its only live effect
            # was on entities carrying both an excluded and an admitted signal,
            # where dropping the excluded one RAISED the term by discarding a real
            # unanswered question — the shape this term exists to stop.
            #
            # A magnitude the fold COMPOSED counts as answered here on the same
            # terms as one the signal carried itself: the answer is a witness
            # either way (the destination function's own flow.out figure), and
            # the whole point of composing it is that the question stops being
            # open. It is counted separately below so a reader can see which of
            # the two supplied it, and composed answers are recorded per signal
            # rather than per entity — an entity carrying two proven reaches of
            # which one composed is 1/2 answered, not answered.
            #
            # A SHEET CEILING is the third path, credited on the same terms and
            # counted apart for the same reason. "How much can this reach move"
            # has been given a proven bound — the controlled node's own priced
            # holdings, which bound it because the code that would have stood in
            # the way is the code the principal can replace — and a question
            # answered with an at-most is not the same as one nobody answered.
            # The credit is NOT vacuous: unlike the codeless credit below it
            # rests on a balance observation, which is why it moves the witnessed
            # term without moving the vacuous share published beside it.
            #
            # The three paths are tried in a fixed order and each signal takes at
            # most one, so the three counters partition the answered population
            # instead of overlapping it. Composition and the sheet ceiling are
            # disjoint by construction anyway — one fires only for gate control
            # and the other only for code control — and the order is what keeps
            # that a property of this loop rather than of a rule elsewhere.
            own = _gate(signal, "reach_magnitude_usd").is_determined
            identity = _signal_identity(signal)
            by_composition = not own and identity in (composed_signals or set())
            by_ceiling = not own and not by_composition and identity in (ceiling_signals or set())
            magnitude[key][1] += 1
            magnitude_census[signal.claim_id][1] += 1
            if own or by_composition or by_ceiling:
                magnitude[key][0] += 1
                magnitude_census[signal.claim_id][0] += 1
                if by_composition:
                    composed_census[signal.claim_id] += 1
                    credit_paths_by_key[key].add(CREDIT_PATH_COMPOSED)
                elif by_ceiling:
                    ceiling_census[signal.claim_id] += 1
                    credit_paths_by_key[key].add(CREDIT_PATH_SHEET_CEILING)
                else:
                    own_witness_signals += 1
                    credit_paths_by_key[key].add(CREDIT_PATH_OWN)

    def weighted(table: dict[str, list[int]]) -> float:
        total = 0.0
        for key in sorted(table):
            answered, seen = table[key]
            if seen and key in perimeter:
                total += perimeter[key] * (answered / seen)
        return round(total, 6)

    codeless_answered = sorted(key for key in perimeter if key in proven_eoas and not scored.get(key, [0, 0])[1])
    for key in codeless_answered:
        reach[key] = [1, 1]
        scored[key] = [1, 1]
        # No code is no capability, and no capability moves no value: there is no
        # reach magnitude here to leave unwitnessed. Same earned getCode witness,
        # same VACUOUS answer — counted in the term and disclosed separately as
        # ``reach_magnitude_vacuous_credit_pct``, because a vacuous answer is not
        # a witness. The pricing term still stands alone.
        magnitude[key] = [1, 1]

    outside = _entities_outside_perimeter(signals, reach, perimeter, value_plane)
    reach_pct = round(100.0 * weighted(reach) / denominator, 1) if denominator else 0.0
    capability_pct = round(100.0 * weighted(scored) / denominator, 1) if denominator else 0.0
    priced_weight = sum(perimeter[k] for k in sorted(perimeter) if value_plane.total(k) is not None)
    priced_pct = round(100.0 * priced_weight / denominator, 1) if denominator else 0.0
    magnitude_pct = round(100.0 * weighted(magnitude) / denominator, 1) if denominator else 0.0
    # The share of the denominator this term could reach at its best: every entity
    # already answered vacuously, plus every reach-carrying entity if all of its
    # proven reaches carried a magnitude witness. Without it a consumer cannot
    # tell how much of the gap is unwitnessed magnitude from how much is perimeter
    # the signal population never covered — two different pieces of work.
    magnitude_ceiling = sum(perimeter[k] for k in sorted(magnitude) if magnitude[k][1] and k in perimeter)
    magnitude_ceiling_pct = round(100.0 * magnitude_ceiling / denominator, 1) if denominator else 0.0
    # Most of this term can be VACUOUS: a proven-codeless entity answers it with
    # no magnitude witness at all. Publishing the headline alone would let a
    # perimeter full of EOAs read as answered magnitude, so the vacuous share is
    # published beside it (term minus this is the witness-backed share of the
    # denominator) together with the witnessed share of the weight that actually
    # carries a proven reach — the figure that only rises when W3/W4b do work.
    vacuous = {key for key in codeless_answered if key in perimeter}
    vacuous_weight = sum(perimeter[key] for key in sorted(vacuous))
    vacuous_pct = round(100.0 * vacuous_weight / denominator, 1) if denominator else 0.0
    reaching = [key for key in sorted(magnitude) if key not in vacuous and magnitude[key][1] and key in perimeter]
    reaching_weight = sum(perimeter[key] for key in reaching)
    reaching_answered = sum(perimeter[key] * (magnitude[key][0] / magnitude[key][1]) for key in reaching)
    witnessed_of_reaching_pct = round(100.0 * reaching_answered / reaching_weight, 1) if reaching_weight else 0.0
    # Counted off the census, not off the weighted table: the table also carries
    # the vacuous credit for proven-codeless entities, which are not signals.
    signals_seen = sum(v[1] for v in magnitude_census.values())
    signals_witnessed = sum(v[0] for v in magnitude_census.values())
    # The term is a per-entity FRACTION, so an entity carrying one witnessed and
    # one unwitnessed proven reach sits at 1/2 — and removing the unwitnessed
    # signal moves it to 1/1, RAISING the term for having proven less.
    #
    # RE-EXAMINED at W4b and WAIVED again, now with a measured bound instead of
    # an argument. Two facts decided it. First, the shape is not this term's: all
    # four terms are the same per-entity answered/seen fraction over the same
    # signal population, so deleting an unanswered signal raises the
    # reachability and capability terms identically — it is a property of the
    # model's shape, and closing it here alone would leave the headline (a MIN
    # over the four) moving on the others anyway. Second, no denominator closes
    # it: every ratio whose denominator counts only the questions that were POSED
    # rises when an unanswered one is deleted, and a denominator that does not
    # shrink would have to count magnitude questions an entity owes independently
    # of its signals — a population nothing in the schema supplies. Denominating
    # over signals rather than entities (the alternative named in the W3 review)
    # has the identical algebra and additionally breaks the min() comparability
    # with the other three terms.
    #
    # So the exposure is SIZED and published rather than closed. An answer the
    # FOLD supplied — a composed destination witness or a sheet ceiling — widens
    # it, because that is what turns a 0/n entity into a mixed one, and the two
    # figures below say by exactly how much: the largest single deletion that
    # could move the term, and the move if every unwitnessed signal at every
    # mixed entity vanished at once. Which of the two did it is MEASURED rather
    # than asserted: the reading names the counts, so a corpus where only one of
    # them fires does not read as though both did.
    mixed = [key for key in sorted(magnitude) if key not in vacuous and 0 < magnitude[key][0] < magnitude[key][1]]
    single_gain = total_gain = 0.0
    for key in mixed:
        answered, seen = magnitude[key]
        weight = perimeter.get(key, 0.0)
        if seen > 1:
            single_gain = max(single_gain, weight * answered / (seen * (seen - 1)))
        total_gain += weight * (1.0 - answered / seen)
    mixed_single_pct = round(100.0 * single_gain / denominator, 2) if denominator else 0.0
    mixed_total_pct = round(100.0 * total_gain / denominator, 2) if denominator else 0.0
    mixed_paths = {key: credit_paths_by_key.get(key, set()) for key in mixed}
    mixed_composed = sum(1 for paths in mixed_paths.values() if CREDIT_PATH_COMPOSED in paths)
    mixed_ceiling = sum(1 for paths in mixed_paths.values() if CREDIT_PATH_SHEET_CEILING in paths)
    # The entities the fold's own answer is the ONLY thing that moved off 0/n:
    # no signal at them carried a magnitude witness of its own, so without the
    # composed figure or the sheet ceiling they would not be in this population
    # at all. A stronger claim than "carries a fold-supplied answer" and the one
    # worth publishing, so it is tested rather than inferred from the counts.
    mixed_fold_only = sum(1 for paths in mixed_paths.values() if paths and CREDIT_PATH_OWN not in paths)
    return {
        "pct": min(reach_pct, capability_pct, priced_pct, magnitude_pct),
        "reachability_answered_pct": reach_pct,
        "capability_scored_pct": capability_pct,
        "value_priced_pct": priced_pct,
        "reach_magnitude_witnessed_pct": magnitude_pct,
        "reach_magnitude_ceiling_pct": magnitude_ceiling_pct,
        # Both in the same units as the term (share of the perimeter denominator),
        # so ``witnessed_pct - vacuous_credit_pct`` is the witness-backed share.
        "reach_magnitude_vacuous_credit_pct": vacuous_pct,
        # Of the perimeter weight that actually carries a proven reach, the share
        # whose magnitude is witnessed. No vacuous credit is in this figure.
        "reach_magnitude_witnessed_of_reaching_pct": witnessed_of_reaching_pct,
        "reach_magnitude_signals": {
            "proven_reach_in_denominator": signals_seen,
            "magnitude_witnessed": signals_witnessed,
            # Of those, the ones answered by COMPOSING the destination
            # function's witness rather than by a witness on the signal's own
            # call. Published apart because they are the same kind of answer
            # arrived at through one more join, and a reader sizing the
            # pipeline's own magnitude coverage needs to be able to subtract
            # them.
            "magnitude_composed": sum(composed_census.values()),
            "composed_by_capability": {k: v for k, v in sorted(composed_census.items())},
            # The THIRD answer, counted apart from both for the reason the
            # composed one is: it carries no call witness at all. The controlled
            # node's own priced sheet bounds the move from above, which is a
            # different and weaker claim than either of the other two, so a
            # reader sizing what the pipeline MEASURED has to be able to
            # subtract it. The name says which ceiling this is —
            # reach_magnitude_ceiling_pct beside it is the term's HEADROOM and
            # is a different quantity entirely.
            "magnitude_sheet_ceiling": sum(ceiling_census.values()),
            "sheet_ceiling_by_capability": {k: v for k, v in sorted(ceiling_census.items())},
            "credit_path_reading": _credit_path_reading(
                {
                    CREDIT_PATH_OWN: own_witness_signals,
                    CREDIT_PATH_COMPOSED: sum(composed_census.values()),
                    CREDIT_PATH_SHEET_CEILING: sum(ceiling_census.values()),
                }
            ),
            "by_capability": {k: v for k, v in sorted(magnitude_census.items())},
            "mixed_witness_entities": len(mixed),
            "mixed_witness_entities_with_a_fold_supplied_answer": {
                CREDIT_PATH_COMPOSED: mixed_composed,
                CREDIT_PATH_SHEET_CEILING: mixed_ceiling,
                "no_own_call_witness_at_all": mixed_fold_only,
            },
            # The size of the monotonicity edge below, in the term's own units.
            # The first is the most the term could rise from deleting ONE
            # unwitnessed proven-reach signal; the second from deleting every
            # unwitnessed signal at every mixed entity.
            "mixed_witness_max_single_deletion_gain_pct": mixed_single_pct,
            "mixed_witness_total_deletion_gain_pct": mixed_total_pct,
            "mixed_witness_reading": (
                "entities carrying BOTH an answered and an unanswered proven reach. The term "
                "is a per-entity fraction, so deleting an unanswered signal from one of these "
                "raises it — a monotonicity edge this model does not close, published rather "
                "than hidden, because every denominator that closes it charges a signal for a "
                "magnitude it does not owe. It is not this term's shape alone: the "
                "reachability and capability terms are the same fraction over the same "
                "population and move the same way. The two gain figures beside this bound the "
                "exposure in the term's own units, so a reader can see what the edge is worth "
                "rather than only that it exists. "
                + _mixed_witness_cause(len(mixed), mixed_composed, mixed_ceiling, mixed_fold_only)
            ),
            "denominator_rule": (
                "EVERY proven-reach signal, with no per-capability exclusions: a capability "
                "that publishes proven_reach is claiming it moves value, so 'how much' is a "
                "question it owes an answer to. The freeze fraction (pause.set) is in the "
                "denominator and unanswered by design until a witness for it exists. On the "
                "numerator side there is no single witness class either: "
                + _credit_path_reading(
                    {
                        CREDIT_PATH_OWN: own_witness_signals,
                        CREDIT_PATH_COMPOSED: sum(composed_census.values()),
                        CREDIT_PATH_SHEET_CEILING: sum(ceiling_census.values()),
                    }
                )
            ),
        },
        "flow_pricing_decidable": {k: v for k, v in sorted(priced.items()) if v[1]},
        "perimeter_entities": len(perimeter),
        # Entities a signal answers FOR or reaches INTO that the denominator
        # never asked about, so the work is invisible to this figure and, for a
        # reach key, the value is charged into a finding while its own
        # unanswered weight sits in no denominator. With the contracts base
        # population this should be empty; a non-empty list is a discovery gap,
        # published rather than absorbed.
        "signal_entities_outside_perimeter": outside,
        "perimeter_value_weighted_denominator": denominator,
        # Each admission rule, counted where it fired, so a consumer can see
        # what the denominator folded or refused rather than inferring it.
        "implementation_entities_folded": len(folded),
        "zero_address_entities_excluded": len(zero_excluded),
        "proven_codeless_answered": len(codeless_answered),
        "discovery_relation_entities_admitted": discovery_admitted,
        "headline_rule": "report the MINIMUM; any larger figure over-claims",
        "monotonicity": (
            "the denominator is the protocol's contracts rows unioned with the value "
            "plane, the walked control closure and every endpoint of every authority "
            "relation discovery recorded — walked or not — folded through the "
            "discovery-fixed implementation alias map, and built without reference to "
            "the signal population, so analysis work can only move value from "
            "unanswered to answered and declining to walk a relation can only charge "
            "confidence, never free it"
        ),
    }


# ---------------------------------------------------------------- disclosures


def _collect_disclosures(
    signal: FunctionSignal,
    earned_negatives: list[dict[str, Any]],
    seen: set[tuple[str, str]],
    warnings: list[dict[str, Any]],
) -> None:
    entity = entity_key(signal.chain, signal.deployment_address)
    credit = _gate(signal, "exact_empty_credit")
    if credit.is_determined:
        if signal.principal_state != PRINCIPAL_STATE_NOT_DETERMINED:
            # "No resolved caller can reach this" cannot be published beside ANY
            # determined caller state: ``enumerated`` names callers that reach it,
            # and ``none_required`` is a PROVEN PUBLIC PATH — the opposite pole,
            # and the worse contradiction of the two.
            warnings.append(
                _warning(
                    "exact_empty_credit_contradicted_by_principals",
                    signal,
                    (
                        "an earned empty caller set on a function with a proven public path"
                        if signal.principal_state == PRINCIPAL_STATE_NONE_REQUIRED
                        else "an earned empty caller set on a function whose principals resolved"
                    ),
                    principal_state=signal.principal_state,
                )
            )
        elif (entity, signal.function_name) not in seen:
            seen.add((entity, signal.function_name))
            payload = credit.value if isinstance(credit.value, dict) else {}
            earned_negatives.append(
                {
                    "entity": entity,
                    "function": signal.function_name,
                    "capability": signal.claim_id,
                    "fact": "no resolved caller can reach this function",
                    "state": "currently_unreachable",
                    "observed_at_block": payload.get("block"),
                    "empty_reason": payload.get("empty_reason"),
                    "counterfactual": "one ownership/authority write restores reachability",
                    "axiom": (
                        "msg.sender != 0x0, so an owner disjunct of {0x0} is a singleton rather than the empty set"
                    ),
                    "re_enablable_by": NOT_DETERMINED,
                }
            )
    if signal.value_state == VALUE_STATE_PROVEN_NO_REACH and (entity, signal.function_name + ":no_reach") not in seen:
        # An earned negative in its own right: reach was WITNESSED and reached
        # nothing. Publishing it beside the undetermined rows would lose the one
        # value fact on the page that was actually proven.
        seen.add((entity, signal.function_name + ":no_reach"))
        earned_negatives.append(
            {
                "entity": entity,
                "function": signal.function_name,
                "capability": signal.claim_id,
                "fact": "reach was witnessed and reached no value",
                "state": "proven_no_reach",
                "basis": signal.value_basis,
                "counterfactual": "funding the entity would give this capability something to reach",
                "re_enablable_by": NOT_DETERMINED,
            }
        )
    latch = _gate(signal, "latch_witness")
    if latch.is_determined:
        payload = latch.value if isinstance(latch.value, dict) else {}
        warnings.append(
            _warning(
                "one_shot_latch_is_reopenable",
                signal,
                "a consumed latch is a now-fact, re-openable by the upgrade authority of the probed proxy",
                latch_state=payload.get("latch_state"),
                probe_block=payload.get("probe_block"),
            )
        )
    for note in signal.witness_notes:
        if note in _NOTE_WARNINGS:
            warnings.append(_warning(note, signal, _NOTE_WARNINGS[note]))


_NOTE_WARNINGS = {
    "destination_not_determined_row_withheld": (
        "the destination was not proven, so no severity is assigned and the row does not "
        "enter the grade; absence of a resolved constraint is not proof the destination is open"
    ),
    "flow_severity_withheld_pending_amount_witness": (
        "the destination is proven caller-relative; what the payout is bounded BY has no witness, "
        "so no severity is assigned and the row does not enter the grade — absence of a bound is "
        "not proof the payout is unbounded"
    ),
    "msg_value_self_return_repetition_not_witnessed": (
        "the amount witness bounds each payment by the value attached to this call; nothing "
        "witnesses how many such payments one call makes"
    ),
    "destination_witnesses_contradict": (
        "two destination witnesses cannot both be true, so neither is adopted and the row is withheld"
    ),
    "caller_arbitrary_escalation_withheld": "caller_arbitrary carries no behavioural existence proof",
    "reach_floor_not_a_bound": "a 0.00 floor is 'no proven bound', not a proven zero",
    "reach_floor_absent": "reach_indeterminate with no floor key: nothing about the balance was witnessed",
    "reach_seeded_balance_only": "the contract's balance was overridden before the payout",
    "reach_partially_priced": "the reach is a proven floor; the unpriced remainder is a confidence gap",
    "freeze_effectiveness_not_determined": (
        "no fork proof that the latch takes effect, so no value membership is charged"
    ),
    "freeze_immobilised_fraction_not_determined": (
        "the value held at the frozen entity is measured; what fraction is immobilised has no witness"
    ),
    "product_claim_reachability_unproven": "treated as product on claim_id alone, but openness is not_determined",
    "claim_type_not_scored": "no severity model exists for this claim type; exclusion is not a benign verdict",
    "restricted_privileged_no_principal": "restricted privileged function with no resolved principal",
    "empty_caller_set_not_earned": (
        "an empty caller set that did not earn the served credit: neither reachable nor "
        "proven unreachable, so no earned negative is published"
    ),
    "registry_escalation_mutators_unverified": "an owner resolves but the role mutator selectors are not present",
    "delay_change_gate_not_self_gated": (
        "the delay-change path's own gate is not the contract itself, so no anti-decoy credit is taken"
    ),
    "destination_redirectable_by_unresolved_setter": "the destination's setter is named by no witness",
    "concrete_destination_existential_not_a_fixed_destination": (
        "an observed sink is existential and cannot prove a fixed destination"
    ),
}


def _warning(kind: str, signal: FunctionSignal, note: str, **extra: Any) -> dict[str, Any]:
    return {
        "kind": kind,
        "entity": entity_key(signal.chain, signal.deployment_address),
        "function": signal.function_name,
        "capability": signal.claim_id,
        "note": note,
        **{k: v for k, v in sorted(extra.items()) if v is not None},
    }


def _summarise_warnings(warnings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        warnings,
        key=lambda w: (
            str(w.get("kind")),
            str(w.get("entity")),
            str(w.get("function")),
            str(w.get("capability")),
            str(w.get("note")),
        ),
    )


def _population_disposition(signals: list[FunctionSignal], findings: list[dict[str, Any]]) -> str:
    if not signals:
        return "no_population(no current signals for this protocol)"
    if not findings:
        return "population_scored_to_nothing(every signal failed closed)"
    return "scored"


def _counterfactual(kind: str) -> str:
    return {
        ANYONE: "gate this capability behind a multisig or timelock",
        "eoa": "move behind a strong multisig (>= 0.67 k/n) or a timelock",
        "safe": "raise the threshold ratio, diversify signers across units, and/or add a timelock in front",
        "timelock": "already timelock-gated; the residual is the proposer quorum and the delay length",
        "contract": "resolve the controlling principal of the gating contract",
    }.get(kind, "n/a")


__all__ = ["GATE_PROVEN_TOKENS", "compute_protocol_score"]
