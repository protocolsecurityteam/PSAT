"""Effects → claims bridge.

Turns a proven effect verdict into a registry claim so the frontend renders it through the shared claims vocabulary
(``site/src/vocab/``).

- The registry is the sole minter: :func:`services.static.claims.registry.emit_claim` and
:func:`resolve_claim_precedence`, never hand-built dicts.
- Fail-closed: only ``proven`` mints. Tier-0 historical verdicts mint only if ``current_check_passed is True``.
- The witness is a pointer (``effect_verdict_id``, ``effect_class``, ``behavior_hash``, ``verdict_tier``) plus a small
observed summary; transcripts stay in the artifact store.

Pure; callers (``workers.effects_worker``, ``services.policy.effective_permissions_writer``) do the I/O.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Protocol

from services.effects.config import (
    EFFECT_CLASS_AUTHORITY_CHANGE,
    EFFECT_CLASS_CODE_UPGRADE,
    EFFECT_CLASS_FREEZE_PAUSE,
    EFFECT_CLASS_SUPPLY,
    EFFECT_CLASS_VALUE_OUT,
    TIER_HISTORICAL,
    VERDICT_PROVEN,
)
from services.static.claims.matchers import discover
from services.static.claims.registry import (
    emit_claim,
    legacy_projections,
    resolve_claim_precedence,
)
from services.static.claims.types import STATIC_TIER_WITNESS_KEY, TIER_PRECEDENCE, Claim, Tier
from utils import claim_ids as C
from utils.execution_record import PROVING_EXECUTION_KEY
from utils.scoring_status import WITNESS_TIER_BEHAVIORAL_OBSERVED

# The effects worker never runs ``build_claims``, so register matcher claims at import (idempotent) so ``emit_claim``
# resolves every id below.
discover()

OBSERVED_TIER: Tier = WITNESS_TIER_BEHAVIORAL_OBSERVED


class VerdictLike(Protocol):
    """The verdict shape the bridge reads (``db.models.EffectVerdict`` or test doubles); read-only members avoid
    invariance friction.
    """

    @property
    def id(self) -> int | None: ...
    @property
    def effect_class(self) -> str: ...
    @property
    def verdict(self) -> str: ...
    @property
    def tier(self) -> str: ...
    @property
    def behavior_hash(self) -> str | None: ...
    @property
    def current_check_passed(self) -> bool | None: ...
    @property
    def witness(self) -> dict[str, Any] | None: ...
    @property
    def observed_residue(self) -> dict[str, Any] | None: ...


def _claim_id_for(verdict: VerdictLike) -> str | None:
    """The claim id for a proven verdict's class, or ``None`` if it carries no present-tense claim."""
    ec = verdict.effect_class
    if ec == EFFECT_CLASS_CODE_UPGRADE:
        return C.UPGRADE_IMPLEMENTATION
    if ec == EFFECT_CLASS_VALUE_OUT:
        return C.FLOW_OUT
    if ec == EFFECT_CLASS_SUPPLY:
        # The recorded sign is the label; absent or unknown fails closed.
        witness = verdict.witness or {}
        sign = witness.get("supply_delta_sign") if isinstance(witness, dict) else None
        if sign == "mint":
            return C.SUPPLY_MINT
        if sign == "burn":
            return C.SUPPLY_BURN
        return None
    if ec == EFFECT_CLASS_FREEZE_PAUSE:
        # The pause recipe only witnesses freezes, so it's always ``pause.set``; ``pause.unset`` stays static-only.
        return C.PAUSE_SET
    if ec == EFFECT_CLASS_AUTHORITY_CHANGE:
        return C.AUTHORITY_GRANT
    return None


def _mints(verdict: VerdictLike) -> bool:
    """Only proven verdicts mint; Tier-0 historical ones need a passed current-state check."""
    if verdict.verdict != VERDICT_PROVEN:
        return False
    if verdict.tier == TIER_HISTORICAL and verdict.current_check_passed is not True:
        return False
    return True


def verdict_to_claim(verdict: VerdictLike) -> Claim | None:
    """Mint the claim for one proven verdict, or ``None``. The witness points at the verdict, never the transcript."""
    if not _mints(verdict):
        return None
    claim_id = _claim_id_for(verdict)
    if claim_id is None:
        return None
    witness: dict[str, Any] = {
        "effect_verdict_id": verdict.id,
        "effect_class": verdict.effect_class,
        "behavior_hash": verdict.behavior_hash,
        "verdict_tier": verdict.tier,
    }
    observed = _observed_summary(verdict)
    if observed:
        witness["observed"] = observed
    return emit_claim(claim_id, OBSERVED_TIER, witness)


def _observed_summary(verdict: VerdictLike) -> dict[str, Any]:
    """A small transcript-free summary of what was observed."""
    raw = verdict.witness if isinstance(verdict.witness, dict) else {}
    # Only keys present on the witness are kept. Contract for the scorer reading ``claim.witness["observed"]``:
    #
    # * Freeze: an absent or empty ``observed_blast_radius`` is an unproven lower bound, not "no freeze" (most freeze
    # verdicts take the no-blast unknown path and mint nothing; score those from the static ``pause.set``, low
    # confidence).
    # * ``duration_bound_seconds`` is a static read, cross-checked on-fork as an upper bound; trust it as a reducer only
    # when ``auto_expiry is True``.
    # * ``duration_bound_seconds is None`` means two things, told apart by ``duration_bound_source``
    # (``config.DURATION_BOUND_*``): ``no_time_reference`` is a proven indefinite latch (most severe; asserted only when
    # nothing in the latch's guard tree could hide a clock read); ``not_determined`` or absent is a confidence gap.
    # * ``pause.unset`` is unwitnessed; don't fabricate it.
    # * ``backing`` (supply.mint only): ``inflow_observed is False`` is witnessed dilution; absence isn't "backed".
    # Transfer counts live on ``observed_residue``.
    # * ``input_seeded`` / ``contract_balance_seeded`` weaken the verdict and must reach the consumer; the latter means
    # "would move value if funded", and its absence doesn't mean funded.
    # * ``destination_shape`` / ``shape_proved_by`` always forwarded (callee-side sinks produced no static flow, leaving
    # reach with no destination). ``shape_proved_by`` is "static", "simulation", or "none" (a confidence gap
    # contributing no severity either way).
    keep = (
        "supply_delta_sign",
        "destination_shape",
        "shape_proved_by",
        # The parameter a ``caller_arbitrary`` proof is about. Without it ``distill._fork_caller_arbitrary_param`` can't
        # tell a call-target sentinel from a payload one and refuses.
        "sentinel_param",
        "gate_mutation",
        "historical",
        "current_capability",
        "pause_effective",
        "observed_blast_radius",
        "auto_expiry",
        "duration_bound_seconds",
        "duration_bound_source",
        "backing",
        "input_seeded",
        "contract_balance_seeded",
        # When the observation was taken and the pin's scope (``config.BLOCK_SOURCES``); absent together when unproven.
        # Absent isn't "current", and verdicts are comparable only at equal heights (``invocation_pin`` doesn't make a
        # run coherent).
        "block_number",
        "block_source",
    )
    summary = {k: raw[k] for k in keep if k in raw}
    summary.update(_reach_summary(verdict))
    summary.update(_execution_summary(verdict))
    if verdict.tier == TIER_HISTORICAL and verdict.current_check_passed is not None:
        summary["current_check_passed"] = verdict.current_check_passed
    return summary


# Downstream value reach, from ``observed_residue`` (per-deployment state, never a cache key), not ``witness``. Scorer
# contract, with ``reach_determined`` as discriminator:
#
# * ``True``: measured; ``observed_reach_value_usd`` is an upper bound over ``observed_reach_holders``.
# * ``False`` with ``reach_indeterminate``: nothing observed leaving a holder, not "no reach". No
# ``observed_reach_value_usd``; ``observed_reach_floor_usd`` is three-state (positive, ``0.0`` weak, or absent meaning
# no balance row). Check key presence, never ``.get()`` into zero.
# * ``False`` without ``reach_indeterminate``: value left but some (holder, asset) pair is unpriced.
# ``observed_reach_unvalued_pairs`` names them; ``observed_reach_priced_usd`` is a partial floor with
# ``observed_reach_priced_holders``; ``observed_reach_unvalued_assets`` is the assets no holder priced (``[]`` is an
# earned negative). Reasons (``unpriced_holding``, ``holdings_at_page_cap``, ``asset_not_in_recorded_holdings``) are
# confidence gaps, never small reach.
# * ``reach_tvl_check``: ``within_protocol_tvl``, ``exceeds_protocol_tvl`` (refused, with
# ``observed_reach_rejected_usd`` and ``protocol_tvl_usd``), or ``skipped_no_tvl``. Applies to whichever figure the row
# publishes; absent when there's no figure.
# * All keys absent: no fork observation at this deployment yet (a cache hit).
_REACH_KEYS = (
    "observed_reach_value_usd",
    "observed_reach_holders",
    "reach_indeterminate",
    "reach_determined",
    "observed_reach_floor_usd",
    "observed_reach_assets",
    "observed_reach_unvalued_pairs",
    "observed_reach_unvalued_assets",
    "observed_reach_unvalued_reasons",
    "observed_reach_priced_usd",
    "observed_reach_priced_holders",
    "reach_tvl_check",
    "observed_reach_rejected_usd",
    "protocol_tvl_usd",
)


def _reach_summary(verdict: VerdictLike) -> dict[str, Any]:
    residue = getattr(verdict, "observed_residue", None)
    if not isinstance(residue, dict):
        return {}
    return {k: residue[k] for k in _REACH_KEYS if k in residue}


# The execution that proved the figures, forwarded with them (F6). Absent is common (older verdicts) and means
# ``not_determined`` (``utils.execution_record``).
def _execution_summary(verdict: VerdictLike) -> dict[str, Any]:
    residue = getattr(verdict, "observed_residue", None)
    if not isinstance(residue, dict) or PROVING_EXECUTION_KEY not in residue:
        return {}
    return {PROVING_EXECUTION_KEY: residue[PROVING_EXECUTION_KEY]}


def claims_from_verdicts(verdicts: Iterable[Any]) -> list[Claim]:
    """Every mintable proven verdict mapped to its claim."""
    out: list[Claim] = []
    for verdict in verdicts:
        claim = verdict_to_claim(verdict)
        if claim is not None:
            out.append(claim)
    return out


# Keys owned by ``verdict_to_claim``. A witness with only these is a pure pointer; anything else came from a static
# matcher (no collisions).
_OBSERVED_WITNESS_KEYS = frozenset({"effect_verdict_id", "effect_class", "behavior_hash", "verdict_tier", "observed"})


def _tier_rank(tier: str | None) -> int:
    return TIER_PRECEDENCE.get(tier or "", 0)


def _carries_static_detail(claim: Claim) -> bool:
    witness = claim.get("witness")
    if not isinstance(witness, dict):
        return False
    return any(key not in _OBSERVED_WITNESS_KEYS for key in witness)


def _donor_for(claim_id: str, prior: list[Claim]) -> Claim | None:
    """The prior claim to inherit structural detail from: the strongest that has any.

    Choosing by tier alone picks an already-stripped observed claim as its own donor, so re-running policy couldn't
    repair damaged rows.
    """
    fallback: Claim | None = None
    donor: Claim | None = None
    for claim in prior:
        if claim.get("claim_id") != claim_id:
            continue
        rank = _tier_rank(claim.get("tier", ""))
        if fallback is None or rank > _tier_rank(fallback.get("tier", "")):
            fallback = claim
        if _carries_static_detail(claim) and (donor is None or rank > _tier_rank(donor.get("tier", ""))):
            donor = claim
    return donor if donor is not None else fallback


def _carry_forward_static_witness(donor: Claim, observed: dict[str, Any]) -> dict[str, Any]:
    """Keep the superseded static witness's structural facts on the observed one.

    A fork observation proves value moved, not where it can go or how much; ``target_kind``, ``amount_kind``,
    ``*_param_index`` etc. are static universals. Dropping them meant the functions we learned most about published
    least.

    The donor's keys are carried in full (families use different keys, so an allowlist under-carried). ``static_tier``
    records where they came from so the observed tier doesn't launder a weak donor; an existing stamp is kept. Observed
    keys win collisions.
    """
    static = donor.get("witness")
    if not isinstance(static, dict):
        return observed
    # The donor's own observation pointer names a different verdict; don't carry it.
    carried = {k: v for k, v in static.items() if k not in _OBSERVED_WITNESS_KEYS}
    if not carried:
        return observed
    merged = dict(carried)
    merged[STATIC_TIER_WITNESS_KEY] = static.get(STATIC_TIER_WITNESS_KEY, donor.get("tier"))
    merged.update(observed)
    return merged


def _drop_superseded(prior: list[Claim], minted: list[Claim]) -> list[Claim]:
    """Drop prior claims a fresh one restates at the same tier; ``resolve_claim_precedence`` keeps the first on a
    tie, so a stale one would win.
    """
    restated = {(claim["claim_id"], claim["tier"]) for claim in minted}
    return [claim for claim in prior if (claim.get("claim_id"), claim.get("tier")) not in restated]


def merge_observed_claims(existing: Iterable[Claim], verdicts: Iterable[Any]) -> list[Claim]:
    """Fold proven verdicts into the claim list under registry precedence.

    Idempotent: observed outranks every static tier and the carry-forward copies the same keys.
    """
    prior = list(existing)
    minted = claims_from_verdicts(verdicts)
    for claim in minted:
        donor = _donor_for(claim["claim_id"], prior)
        if donor is not None:
            claim["witness"] = _carry_forward_static_witness(donor, claim.get("witness") or {})
    return resolve_claim_precedence([*_drop_superseded(prior, minted), *minted])


def reproject_effect_labels(existing_labels: Iterable[str], claims: Iterable[Claim]) -> list[str]:
    """Rebuild legacy ``effect_labels`` as existing labels plus every claim's ``legacy_projection`` (additive, like
    ``project_effect_labels``).
    """
    projections = legacy_projections()
    labels = {str(label) for label in existing_labels}
    for claim in claims:
        projected = projections.get(claim.get("claim_id", ""))
        if projected:
            labels.add(projected)
    return sorted(labels)


def merge_into_function(
    existing_claims: Iterable[Claim] | None,
    existing_labels: Iterable[str] | None,
    verdicts: Iterable[Any],
) -> tuple[list[Claim], list[str]] | None:
    """Fold proven verdicts into the claims, then re-project labels.

    Returns ``(claims, effect_labels)``, or ``None`` when nothing minted so untouched rows stay byte-identical.

    Must go through :func:`merge_observed_claims`; an inlined copy once diverged and deleted the static lattice.
    """
    existing_claims = list(existing_claims or [])
    if not claims_from_verdicts(verdicts):
        return None
    merged_claims = merge_observed_claims(existing_claims, verdicts)
    merged_labels = reproject_effect_labels(existing_labels or [], merged_claims)
    return merged_claims, merged_labels
