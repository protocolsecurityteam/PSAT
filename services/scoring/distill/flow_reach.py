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
    reach_determined = _is_true(observed.get("reach_determined"))
    value_usd = _f(observed.get("observed_reach_value_usd")) if reach_determined else None
    holders = [_lower(h) for h in (observed.get("observed_reach_holders") or []) if h]

    if reach_determined and value_usd is not None:
        keys = tuple(sorted({entity_key(facts.chain, h) for h in holders}))
        if value_usd > 0.0 and not keys:
            # Holder unnamed: publish as unattributed rather than misattribute to this deployment.
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
            # The entity-set bound (every named holder), distinct from the dollar magnitude state.
            bound=VALUE_BOUND_EXACT,
            entity_keys=keys,
            basis="observed_reach_value_usd(fork-proven)",
            # F4: attribution path. The probe moved a constant and ``recipes._add_reach`` credited the holder's whole
            # balance, so this is an upper bound, not exact, and not a floor either.
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
        # A 0.0 floor proves nothing: an unpriced sheet sums to the same zero.
        return _no_reach(
            "observed_reach_floor_usd_zero(not_determined)" if gated else "observed_reach_floor_usd_ungated",
            ("reach_floor_not_a_bound",),
        )
    if gated:
        # No balance row for the acting deployment, so no floor.
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
        # Balance was seeded before the payout: proves capability, not an outflow of real treasury.
        return _no_reach("contract_balance_seeded(not_determined)", ("reach_seeded_balance_only",))
    return _no_reach("reach_not_witnessed(not_determined)")


def _proving_execution_gate(facts: _ContractFacts, func: Any, entries: list[dict[str, Any]]) -> Tri[dict[str, Any]]:
    """The execution that proved this signal's magnitude, as a gate envelope.

    Both gate states are proven ("does a record exist" is always answerable); the record's three-state answer and typed
    reason ride in the payload, since a ``Tri.not_determined()`` envelope can't carry a reason.

    Read from the claim witness when persisted, else from the verdict's transcript (:class:`_TranscriptReader`);
    transcript faults keep their own reason. The entry comes from :func:`_cited_verdict_entry`, so the execution and the
    published ``effect_verdict_id`` are the same row by construction.
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
    return [e for e in entries if ((e.get("witness") or {}).get("effect_verdict_id")) is not None]


def _cited_verdict_entry(entries: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The one entry whose verdict this signal is about, or ``None``.

    The last verdict-bearing entry, matching the existing ``effect_verdict_id`` rule. Two verdicts on one claim are
    ambiguous and disclosed at the call site; stored order isn't evidence.
    """
    bearing = _verdict_bearing_entries(entries)
    return bearing[-1] if bearing else None


def _repointed_entities(
    entry: dict[str, Any], facts: _ContractFacts
) -> tuple[list[str], list[str], list[dict[str, Any]]]:
    """Entities the witness itself names as where the value is.

    A repoint adds a foreign entity to reach, so it gets the backlink licence's checks:

    * the tier must be in the ``REPOINT_ADMISSIBLE_TIERS`` allowlist (``policy_derived`` and ``not_determined`` are
    inferences, not value evidence);
    * the address must be a contract of this protocol on this chain;
    * the burn address is never an entity.

    A repoint never supplies a magnitude or upgrades ``value_state``. Refusals are returned so declined reach is
    visible.
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
