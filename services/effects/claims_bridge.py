"""Effects → claims bridge (EFFECTS_RESOLUTION_SPEC §5.2).

Turns a *proven* effect verdict into a registry claim so the frontend renders it
through the one shared claims vocabulary (``site/src/claimsVocab.js``) with zero
duplicated display logic. This is the Phase-5 consumption boundary: the write-
only substrate (§3a) becomes "labels-observable, scoring-deferred".

Design constraints this module honours verbatim:

- **Registry is the sole minter.** Claims are built only through
  :func:`services.static.claims.registry.emit_claim` and collapsed through
  :func:`resolve_claim_precedence` — never hand-built dicts. An id not in the
  registry cannot escape (the same anti-creep invariant static relies on).
- **Fail-closed (§8).** Only ``verdict == proven`` mints. ``unknown`` / degraded
  mint nothing. A Tier-0 *historical* verdict mints only when its current-state
  check passed (``current_check_passed is True``); a failed current check proves
  *past* capability, and a present-tense label would overclaim.
- **Witness is a pointer, not a payload.** The claim witness records the verdict
  identity (``effect_verdict_id`` / ``effect_class`` / ``behavior_hash`` /
  ``verdict_tier``) plus a minimal observed summary. Transcripts never enter
  ``EffectiveFunction.claims`` — they live in the artifact store (§8.5).

Pure functions, no I/O: the two call sites (``workers.effects_worker`` and
``services.policy.effective_permissions_writer``) do the DB reads/writes and
hand this module plain verdict-shaped objects.
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
    RegistryEntry,
    emit_claim,
    is_registered,
    legacy_projections,
    register,
    resolve_claim_precedence,
)
from services.static.claims.types import Claim

# The effects worker runs in its own process and never calls ``build_claims``, so
# the standard matcher claims (``upgrade.implementation``, ``flow.out``, …) would
# not be registered when the bridge emits. Populate the registry at import — the
# same import every matcher module runs, idempotent — so ``emit_claim`` resolves
# every id the mapping below reaches.
discover()

# The observed-authority claim (§5.2 mapping): what the authority-change recipe
# actually proves is that calling F opens a permission gate to callers that
# previously could not pass it (``recipes.authority_change`` — ≥2 random
# identities rejected before, all accepted after). None of the existing static
# authority sentences is honest for that: ``roles.grant`` asserts a *recognized-
# standard* role scheme, ``authority.replace`` a contract swap,
# ``authorized_caller.rotate`` a scalar-pointer rotation — the mechanism-agnostic
# witness proves none of those. So it gets its own honest id, registered like the
# policy-tier ``transfer_policy.configure``: never minted by the static pass
# (gate/trigger inert), only by this bridge through ``emit_claim``.
AUTHORITY_GRANT = "authority.grant"


def _no_static_gate(_ctx: Any) -> bool:
    return False


def _no_static_trigger(_ctx: Any, _function: str) -> None:
    return None


if not is_registered(AUTHORITY_GRANT):
    register(
        RegistryEntry(
            claim_id=AUTHORITY_GRANT,
            sentence="lets a caller pass a permission gate that previously rejected it",
            gate=_no_static_gate,
            trigger=_no_static_trigger,
            legacy_projection="authority_update",
            consumer_family="control_plane",
        )
    )

# The provenance tier every bridge-minted claim carries.
OBSERVED_TIER = "behavioral_observed"


class VerdictLike(Protocol):
    """The verdict shape the bridge reads — satisfied by ``db.models.EffectVerdict``
    and by lightweight test doubles. Read-only members so a concrete row (whose
    ``id`` is a non-null ``int``) structurally matches without invariance friction."""

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
    """The honest claim id for a proven verdict's effect class, or ``None`` when
    the class carries no present-tense existential claim."""
    ec = verdict.effect_class
    if ec == EFFECT_CLASS_CODE_UPGRADE:
        return "upgrade.implementation"
    if ec == EFFECT_CLASS_VALUE_OUT:
        return "flow.out"
    if ec == EFFECT_CLASS_SUPPLY:
        # The recipe records a signed delta as ``supply_delta_sign`` (mint/burn);
        # the sign IS the label. Absent/unknown sign fails closed (no claim).
        witness = verdict.witness or {}
        sign = witness.get("supply_delta_sign") if isinstance(witness, dict) else None
        if sign == "mint":
            return "supply.mint"
        if sign == "burn":
            return "supply.burn"
        return None
    if ec == EFFECT_CLASS_FREEZE_PAUSE:
        # The pause recipe only ever witnesses a FREEZE (entry points that newly
        # revert after the latch flip) — it has no unpause direction — so a proven
        # freeze_pause verdict is always ``pause.set``. ``pause.unset`` stays a
        # static-only claim until an unfreeze recipe exists to witness it.
        return "pause.set"
    if ec == EFFECT_CLASS_AUTHORITY_CHANGE:
        return AUTHORITY_GRANT
    return None


def _mints(verdict: VerdictLike) -> bool:
    """§8 fail-closed gate: only a proven verdict mints, and a Tier-0 historical
    verdict mints only when its current-state check passed (inv. 13)."""
    if verdict.verdict != VERDICT_PROVEN:
        return False
    if verdict.tier == TIER_HISTORICAL and verdict.current_check_passed is not True:
        return False
    return True


def verdict_to_claim(verdict: VerdictLike) -> Claim | None:
    """Mint the registry claim for one proven verdict, or ``None`` when the
    verdict fails the §8 gate or maps to no claim. The witness is a pointer to the
    verdict (never the transcript)."""
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
    """A tiny, transcript-free summary of what was observed — enough to read the
    witness without opening the artifact. Never the raw transcript (§8.5)."""
    raw = verdict.witness if isinstance(verdict.witness, dict) else {}
    # ``observed_blast_radius`` / ``auto_expiry`` / ``duration_bound_seconds`` are the
    # freeze-severity fields the fork pause recipe records on ``effect_verdicts.witness``
    # (§4.1, ``anvil.pause_recipe``). The dict-comp keeps only keys PRESENT on the
    # witness, so adding them is a no-op for every non-freeze class.
    #
    # CONTRACT for the eventual scorer that reads ``claim.witness["observed"]`` — these
    # fallbacks are load-bearing; a consumer that ignores them re-introduces the exact
    # "empty blast radius reads as harmless" bug this projection exists to fix:
    #   * An absent/empty ``observed_blast_radius`` is NOT "no freeze" — it is an
    #     UNPROVEN LOWER BOUND. Only 7/65 freeze_pause verdicts observe a radius; the
    #     other 58 take the no-blast ``unknown`` path (``anvil.py``) and mint NO
    #     behavioral claim at all (the ``_mints`` gate), keeping only a static
    #     ``pause.set``. Score those from the static claim, flagged low-confidence —
    #     never as a proven harmless pause.
    #   * ``duration_bound_seconds`` is a STATIC read (``calldata.read_max_pause_duration``),
    #     cross-checked on-fork only as an upper bound. Trust it as a severity-REDUCER
    #     ONLY when ``auto_expiry is True``; ``auto_expiry is False`` means the fork
    #     contradicted the static constant, so the bound is not a mitigation.
    #   * ``duration_bound_seconds is None`` + ``auto_expiry is None`` = an INDEFINITE
    #     LATCH = the MOST severe freeze, never zero/short.
    #   * ``pause.unset`` is entirely unwitnessed (no unfreeze recipe; freeze_pause always
    #     maps to ``pause.set``). Do not fabricate an unset/auto-recover fact from these.
    # ``backing`` (§5a) is the fork-observed mint-backing object
    # ``{inflow_observed, minted, ...}`` recorded on EFFECT_CLASS_SUPPLY verdicts —
    # present only on ``supply.mint``. ``inflow_observed is False`` is a witnessed
    # dilution signal (supply rose with no asset inflow in the same call); the
    # scorer must NOT read absence of this key as "backed". The per-execution
    # Transfer COUNTS are state-plane and live on ``observed_residue``
    # (``backing_inflow_transfers`` / ``backing_mint_transfers``), absent on a
    # deployment whose verdict came from a cache hit.
    #
    # ``input_seeded`` / ``contract_balance_seeded`` are the SYNTHESIS QUALIFIERS of
    # a proven verdict and both weaken it — they must reach the consumer or the
    # claim reads stronger than the observation:
    #   * ``input_seeded`` — the acting principal was given the input asset the
    #     function pulls. The effect itself is still fully observed; what is NOT
    #     claimed is that this principal holds that asset today.
    #   * ``contract_balance_seeded`` — the TARGET CONTRACT's own ETH balance was
    #     overridden before the payout executed. The verdict then means "would move
    #     value if the contract were funded" (a capability of the code), NOT "moves
    #     value in current state". A scorer must not treat it as a live outflow of
    #     present treasury, and must not read its ABSENCE as "the contract is
    #     funded" — absence only means no balance override was needed.
    keep = (
        "supply_delta_sign",
        "gate_mutation",
        "historical",
        "current_capability",
        "pause_effective",
        "observed_blast_radius",
        "auto_expiry",
        "duration_bound_seconds",
        "backing",
        "input_seeded",
        "contract_balance_seeded",
    )
    summary = {k: raw[k] for k in keep if k in raw}
    summary.update(_reach_summary(verdict))
    if verdict.tier == TIER_HISTORICAL and verdict.current_check_passed is not None:
        summary["current_check_passed"] = verdict.current_check_passed
    return summary


# §5b downstream value-reach. Read from ``effect_verdicts.observed_residue``, NOT
# from ``witness``: holder addresses and USD are per-deployment state, and while
# they lived on the witness they were copied into the code-plane behavioral cache
# and re-published as a DIFFERENT deployment's observation on every cache hit.
# ``observed_residue`` is the state-plane column and is never a cache key (inv. 3).
#
# CONTRACT for the eventual scorer: the reach USD is a conservative upper bound (a
# holder's full on-chain balance attributed when value provably leaves it, inv.
# 5/7); ``reach_indeterminate is True`` means downstream reach was fork-observed to
# be nothing, so the value is FLOORED to the acting deployment's own balance —
# never inflated via a control-graph heuristic. ABSENCE of all three keys is NOT
# "no reach": it means this deployment has no fork observation of its own yet (its
# verdict came from a cache hit), so reach is simply unmeasured here.
_REACH_KEYS = ("observed_reach_value_usd", "observed_reach_holders", "reach_indeterminate")


def _reach_summary(verdict: VerdictLike) -> dict[str, Any]:
    residue = getattr(verdict, "observed_residue", None)
    if not isinstance(residue, dict):
        return {}
    return {k: residue[k] for k in _REACH_KEYS if k in residue}


def claims_from_verdicts(verdicts: Iterable[Any]) -> list[Claim]:
    """Every mintable proven verdict, mapped to its claim (fail-closed drops
    filtered out)."""
    out: list[Claim] = []
    for verdict in verdicts:
        claim = verdict_to_claim(verdict)
        if claim is not None:
            out.append(claim)
    return out


# Structural keys a STATIC value-flow witness owns and an observed one never
# measures: which sinks, in which direction, to what kind of destination, for
# what kind of amount, at which ABI slot.
_STATIC_FLOW_KEYS = ("kind", "direction", "flows", "sink_ids")


def _carry_forward_static_witness(static: Any, observed: dict[str, Any]) -> dict[str, Any]:
    """Keep the superseded static witness's structural facts on the observed one.

    Precedence is about TIER — how well we know the claim is true — and a fork
    observation is the strongest evidence that value moved. It is not evidence
    about WHERE it can go or HOW MUCH: the probe watched one execution, while
    ``target_kind``/``amount_kind``/``*_param_index`` are universals the static
    lattice derived from the code. Dropping them because a stronger tier arrived
    discarded the only answer to the question the stage exists to ask.

    The effect was perverse: the claim survived at ``behavioral_observed`` while
    its destination and amount vanished, so the functions we learned the MOST
    about published the LEAST. Of four sibling ``EtherFiRedemptionManager.redeem*``
    with identical static flow sets, the one whose probe actually executed was the
    only one to lose its lattice.

    Observed keys always win on a collision — the observation is the newer, better
    evidence about anything it genuinely measured."""
    if not isinstance(static, dict):
        return observed
    merged = {k: static[k] for k in _STATIC_FLOW_KEYS if k in static}
    merged.update(observed)
    return merged


def merge_observed_claims(existing: Iterable[Claim], verdicts: Iterable[Any]) -> list[Claim]:
    """Fold this function's proven verdicts into its existing claim list under the
    registry precedence rule. Idempotent: re-merging the same verdicts is a no-op
    because ``resolve_claim_precedence`` keeps one claim per (id, strongest tier)
    and ``behavioral_observed`` outranks every static tier, so a second pass finds
    nothing stronger to install — and the carry-forward below is itself
    idempotent, since re-merging copies the same structural keys back."""
    prior = list(existing)
    minted = claims_from_verdicts(verdicts)
    strongest_static = {claim["claim_id"]: claim for claim in resolve_claim_precedence(prior)}
    for claim in minted:
        superseded = strongest_static.get(claim["claim_id"])
        if superseded is not None:
            claim["witness"] = _carry_forward_static_witness(superseded.get("witness"), claim.get("witness") or {})
    return resolve_claim_precedence([*prior, *minted])


def reproject_effect_labels(existing_labels: Iterable[str], claims: Iterable[Claim]) -> list[str]:
    """Re-derive the legacy ``effect_labels`` as the union of the labels already
    present and the registry ``legacy_projection`` of every claim on the function
    (the same additive dual-write discipline ``project_effect_labels`` uses), so
    the legacy display path stays in sync with the claims plane."""
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
    """The whole per-function merge: fold proven verdicts into the claims, then
    re-project the legacy labels. Returns ``(claims, effect_labels)`` or ``None``
    when nothing minted (so a caller leaves untouched rows exactly as written —
    the identity path keeps every claim-free function byte-identical)."""
    existing_claims = list(existing_claims or [])
    minted = claims_from_verdicts(verdicts)
    if not minted:
        return None
    merged_claims = resolve_claim_precedence([*existing_claims, *minted])
    merged_labels = reproject_effect_labels(existing_labels or [], merged_claims)
    return merged_claims, merged_labels
