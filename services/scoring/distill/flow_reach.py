"""Flow reach and proving-execution reads."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from services.scoring.schema import (
    Tri,
    entity_key,
)
from utils import execution_record as EX
from utils.execution_record import PROVING_EXECUTION_KEY
from utils.scoring_status import (
    MAGNITUDE_STATE_PROVEN_FLOOR,
    MAGNITUDE_STATE_PROVEN_UPPER_BOUND,
    VALUE_BOUND_EXACT,
    VALUE_BOUND_FLOOR,
    VALUE_BOUND_NOT_DETERMINED,
    VALUE_STATE_NOT_DETERMINED,
    VALUE_STATE_PROVEN_NO_REACH,
    VALUE_STATE_PROVEN_REACH,
    WITNESS_TIER_POLICY_DERIVED,
)

from .claims import _tier
from .facts import (
    REPOINT_ADMISSIBLE_TIERS,
    _ContractFacts,
    _f,
    _is_true,
    _lower,
    _proven_number,
)

logger = logging.getLogger("services.scoring.distill")

# ---------------------------------------------------------------- reach/value


@dataclass(frozen=True)
class _Reach:
    state: str
    bound: str
    entity_keys: tuple[str, ...]
    basis: str
    magnitude: Tri[float]
    notes: tuple[str, ...] = ()


def _no_reach(basis: str, notes: tuple[str, ...] = ()) -> _Reach:
    return _Reach(
        state=VALUE_STATE_NOT_DETERMINED,
        bound=VALUE_BOUND_NOT_DETERMINED,
        entity_keys=(),
        basis=basis,
        magnitude=Tri[float].not_determined(),
        notes=notes,
    )


def _flow_reach(observed: dict[str, Any], facts: _ContractFacts, acting_key: str) -> _Reach:
    """The magnitude a flow is PROVEN to reach, and whose value it is."""
    reach_determined = _is_true(observed.get("reach_determined"))
    value_usd = _f(observed.get("observed_reach_value_usd")) if reach_determined else None
    holders = [_lower(h) for h in (observed.get("observed_reach_holders") or []) if h]

    if reach_determined and value_usd is not None:
        keys = tuple(sorted({entity_key(facts.chain, h) for h in holders}))
        if value_usd > 0.0 and not keys:
            # A proven magnitude whose HOLDER was never named belongs to an
            # entity this signal cannot identify. Attributing it to the analysed
            # deployment is the entity misattribution the register measures in
            # dollars, so the magnitude is published as unattributed instead.
            return _no_reach("observed_reach_value_usd_without_holder(not_determined)", ("reach_holder_not_named",))
        if value_usd <= 0.0 and not holders:
            return _Reach(
                state=VALUE_STATE_PROVEN_NO_REACH,
                bound=VALUE_BOUND_NOT_DETERMINED,
                entity_keys=(),
                basis="observed_reach_value_usd=0(proven)",
                magnitude=Tri[float].not_determined(),
            )
        return _Reach(
            state=VALUE_STATE_PROVEN_REACH,
            # The ENTITY-SET bound, and it is exact here: ``keys`` is every
            # holder the observation named, not a floor over them. A different
            # axis from the magnitude state below, which grades the DOLLARS.
            bound=VALUE_BOUND_EXACT,
            entity_keys=keys,
            basis="observed_reach_value_usd(fork-proven)",
            # F4. This is the ATTRIBUTION path: the probe moved a compile-time
            # constant amount and ``recipes._add_reach`` credited the holder's
            # ENTIRE priced balance for the pair, discarding the transferred
            # value. Nothing here witnesses that the call moves that balance, so
            # the figure is an upper bound on what one call moves — exactness is
            # unearnable in principle on this path. It is not re-pointed at
            # ``proven_floor`` either: that state's prose means "at least this
            # much", and this figure bounds the opposite direction.
            magnitude=_proven_number(MAGNITUDE_STATE_PROVEN_UPPER_BOUND, value_usd),
            notes=("reach_holder_is_not_this_entity",) if holders and acting_key not in keys else (),
        )

    gated = _is_true(observed.get("reach_indeterminate"))
    if "observed_reach_floor_usd" in observed:
        floor = _f(observed.get("observed_reach_floor_usd"))
        if gated and floor is not None and floor > 0.0:
            return _Reach(
                state=VALUE_STATE_PROVEN_REACH,
                bound=VALUE_BOUND_FLOOR,
                entity_keys=(acting_key,),
                basis="observed_reach_floor_usd(>= floor, reach_indeterminate)",
                magnitude=_proven_number(MAGNITUDE_STATE_PROVEN_FLOOR, floor),
            )
        # A 0.0 floor is "no proven bound": an all-unpriced sheet sums to the
        # same zero as a proven-empty one, and an ungated floor is not the
        # registered shape at all.
        return _no_reach(
            "observed_reach_floor_usd_zero(not_determined)" if gated else "observed_reach_floor_usd_ungated",
            ("reach_floor_not_a_bound",),
        )
    if gated:
        # The key's own ABSENCE is the third state: no balance row existed for
        # the acting deployment, so there is no floor to state.
        return _no_reach("observed_reach_floor_absent(not_determined)", ("reach_floor_absent",))

    priced = _f(observed.get("observed_reach_priced_usd"))
    if priced is not None:
        priced_holders = [_lower(h) for h in (observed.get("observed_reach_priced_holders") or []) if h]
        keys = tuple(sorted({entity_key(facts.chain, h) for h in priced_holders})) or (acting_key,)
        return _Reach(
            state=VALUE_STATE_PROVEN_REACH,
            bound=VALUE_BOUND_FLOOR,
            entity_keys=keys,
            basis="observed_reach_priced_usd(>= floor)",
            magnitude=_proven_number(MAGNITUDE_STATE_PROVEN_FLOOR, priced),
            notes=("reach_partially_priced",),
        )
    if _is_true(observed.get("contract_balance_seeded")):
        # The contract's own balance was overridden before the payout, so the
        # verdict proves a code capability, not an outflow of present treasury.
        return _no_reach("contract_balance_seeded(not_determined)", ("reach_seeded_balance_only",))
    return _no_reach("reach_not_witnessed(not_determined)")


def _proving_execution_gate(facts: _ContractFacts, func: Any, entries: list[dict[str, Any]]) -> Tri[dict[str, Any]]:
    """The execution that proved this signal's magnitude, as a gate envelope.

    The gate answers a question the distiller can ALWAYS answer — "does a
    persisted execution record exist for this signal?" — which is why both of its
    states are proven. The record's own three-state answer to the different
    question ("what execution proved this figure?") rides inside the payload,
    together with the typed reason where there is none. It has to be spelled that
    way round: a ``Tri.not_determined()`` envelope may carry no value at all, so
    routing the negative through it would delete the reason, and a reader could
    not tell a row that predates the record from a transcript that failed to
    store.

    Read off the claim witness the effects→claims bridge projects wherever the
    record is persisted — that is the cheap path and the one every future verdict
    takes. Where the residue carries none, the verdict's own transcript is read
    (:class:`_TranscriptReader`), because the call IS in there and "not written
    to the column" is not "not determined". Every verdict in the reference corpus
    predates the write, so the fallback is the whole of the corpus's coverage
    today and the fast path is the whole of it tomorrow. A fault reaching the
    transcript keeps its own reason and is NOT collapsed into the residue's.

    Which entry is read is :func:`_cited_verdict_entry`'s decision and NOT this
    function's, so the execution published here and the ``effect_verdict_id`` the
    signal publishes are the same row by construction rather than by two
    independent scans that happen to agree. They did not agree before: this
    function took the FIRST verdict-bearing entry and the signal took the LAST,
    which on a claim carrying two would have paired one verdict's dollars with
    another's caller — the failure ``_destination_magnitudes`` forbids one file
    over. (No signal in the reference corpus carries two, so the disagreement was
    latent; a comment asserting an invariant the code did not hold is the part
    that was live.)
    """
    entry = _cited_verdict_entry(entries)
    if entry is None:
        return Tri.proven(EX.GATE_STATE_NOT_RECORDED, EX.not_determined(EX.REASON_NO_VERDICT).as_json())
    witness = entry.get("witness") or {}
    verdict_id = int(witness["effect_verdict_id"])
    verdict = next((v for v in facts.verdicts.get(func.id, []) if v.id == verdict_id), None)
    if verdict is None:
        record = EX.not_determined(EX.REASON_VERDICT_NOT_LOCATED, effect_verdict_id=verdict_id)
    else:
        observed = witness.get("observed") or {}
        transcript_ptr = getattr(verdict, "transcript_ptr", None)
        record = EX.from_residue(
            observed.get(PROVING_EXECUTION_KEY),
            transcript_ptr=transcript_ptr,
            effect_verdict_id=verdict_id,
        )
        if not record.is_recorded and facts.transcripts is not None:
            record = facts.transcripts.execution(transcript_ptr=transcript_ptr, effect_verdict_id=verdict_id)
    state = EX.GATE_STATE_RECORDED if record.is_recorded else EX.GATE_STATE_NOT_RECORDED
    return Tri.proven(state, record.as_json())


def _verdict_bearing_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every claim entry naming an effect verdict, in stored order."""
    return [e for e in entries if ((e.get("witness") or {}).get("effect_verdict_id")) is not None]


def _cited_verdict_entry(entries: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The ONE entry whose verdict this signal is about, or ``None``.

    The LAST verdict-bearing entry, which is the rule the published
    ``effect_verdict_id`` already used — preserved rather than replaced, because
    changing which verdict a signal cites is a claim change and this seam exists
    to remove a disagreement, not to introduce one.

    A claim carrying TWO verdicts is a genuine ambiguity and is disclosed at the
    call site rather than resolved silently here: the rule below is stored order,
    which is not evidence about which verdict the claim is really about.
    """
    bearing = _verdict_bearing_entries(entries)
    return bearing[-1] if bearing else None


def _repointed_entities(
    entry: dict[str, Any], facts: _ContractFacts
) -> tuple[list[str], list[str], list[dict[str, Any]]]:
    """Entities the witness itself names as where the value is / what is affected.

    A repoint adds a foreign entity to a reach set, which is the same act as the
    backlink licence one screen up — and it was performed with none of that
    function's checks: no protocol, no chain, no existence, and no check that the
    witness naming the entity is a witness that proved anything about value.

    Three admissions, each earned:

    * The witness must be a VALUE witness, and that is tested as an ALLOWLIST of
      the tiers that are one (``REPOINT_ADMISSIBLE_TIERS``). A denylist of
      ``policy_derived`` would admit every tier nobody has classified — including
      the ``not_determined`` an absent or unrecognised ``tier`` token falls to,
      which is precisely a witness that proved nothing. A ``policy_derived``
      claim is a static inference — the ``configures`` producer's own docstring
      concedes that "the written set-var stands in for the spec's 'read by the
      hook fn'" — and an inference about what a function configures is not
      evidence about where value sits.
    * The named address must be a contract of THIS protocol on THIS chain, the
      same three checks :func:`_licensed_reach_entities` makes.
    * The burn address is never an entity. It is the graph's single largest
      fan-out and the sentinel every renunciation writes.

    A repoint never supplies a magnitude and never upgrades ``value_state``:
    naming a callee proves a call, not that value moves. Refusals are returned
    rather than dropped, so a reach this scorer declined is visible on the signal
    instead of being absent from it.
    """
    from services.scoring.planes import is_zero_key

    witness = entry.get("witness") or {}
    keys: list[str] = []
    bases: list[str] = []
    refused: list[dict[str, Any]] = []
    tier = _tier(entry)
    for field_name, basis in (("callee", "witness.callee"), ("configures", "witness.configures")):
        named = witness.get(field_name)
        if not named:
            continue
        key = entity_key(facts.chain, named)
        if tier == WITNESS_TIER_POLICY_DERIVED:
            why = "witness_tier_policy_derived(a static inference, not a value witness)"
        elif tier not in REPOINT_ADMISSIBLE_TIERS:
            why = f"witness_tier_not_determined({tier}; no tier token this scorer can vouch for)"
        elif is_zero_key(key):
            why = "zero_address_is_a_burn_sentinel_not_an_entity"
        elif key not in facts.protocol_entities:
            why = "named_entity_is_not_a_contract_of_this_protocol_on_this_chain"
        else:
            keys.append(key)
            bases.append(basis)
            continue
        refused.append({"entity_key": key, "basis": basis, "witness_tier": tier, "why": why})
    return keys, bases, refused
