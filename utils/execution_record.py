"""The execution that PROVED a magnitude — one closed shape, read by two planes.

A published magnitude has to carry the execution that produced it: caller,
target, selector, calldata, block, seeded-or-not. Today that execution exists
only inside the transcript blob in object storage — ``harness.record_calls``
writes it and nothing downstream can reach it, so every consumer of the figure
sees a number with no account of the call that proved it.

This module is the one place the record's field names, its closed reason
vocabulary and its three-state reading are written down. Two planes import it
and neither imports the other:

* the PRODUCER (``services.effects.recipes``) builds :func:`residue_payload`
  from the call it actually issued and hands it back on
  ``ObservedEffect.concrete``, the half the worker routes to
  ``effect_verdicts.observed_residue``;
* the CONSUMER (``services.scoring.distill``) reads it back off the claim
  witness the effects→claims bridge projects, and hands the fold a
  :class:`ProvingExecution`.

**State plane, never the code plane.** A caller address, a block height and a
seeding decision are one deployment's observation of one fork. The record must
never enter ``effect_behavior_cache`` (``db/models.py``), which is keyed on
``behavior_hash`` with no address by design — a cache hit would republish some
OTHER deployment's caller as this one's proof. ``concrete`` is the half that
never reaches that table, which is why the payload rides there and not on
``details``.

**Absence is the third state, and it is the common one.** Every verdict written
before this record existed carries no key at all. A consumer must read that as
:data:`REASON_NOT_PERSISTED` — never as "there was no caller", never as an
unseeded probe, and never as licence to publish the figure as if the execution
were known. The same rule governs ``input_seeded`` /
``contract_balance_seeded``: the harness writes those keys only on the recipes
that consider seeding, so an absent key conflates "not seeded" with "seeding was
never a question here" and must read as :data:`SEEDING_NOT_DETERMINED`.

**Nothing here decodes calldata.** ``calldata`` is published raw, always. A
decoded argument list is only honest against the destination selector's own
stored ABI signature, and a positional guess off a byte slice is the same
laundering this record exists to stop — so ``decoded`` is a separate, later
question and this shape carries the bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

# The ``effect_verdicts.observed_residue`` key, and the ``gate_inputs`` name the
# distiller writes it under. One string, so a rename cannot desynchronise the
# two ends.
PROVING_EXECUTION_KEY = "proving_execution"

# The record's own three-state answer to "what execution proved this figure".
EXECUTION_RECORDED = "recorded"
EXECUTION_NOT_DETERMINED = "not_determined"

# The gate's answer to a DIFFERENT question — "does a persisted record exist for
# this signal" — which the distiller can always answer because it performed the
# lookup. Both tokens are proven; the earned negative carries the typed reason
# as its payload, which a ``Tri.not_determined()`` envelope could not (it is
# forbidden to carry a value at all). The two vocabularies are kept apart on
# purpose: "we looked and there is none" is not "the execution is unknown for a
# reason we did not record".
GATE_STATE_RECORDED = EXECUTION_RECORDED
GATE_STATE_NOT_RECORDED = "not_recorded"
GATE_STATES = (GATE_STATE_RECORDED, GATE_STATE_NOT_RECORDED)

# Why no execution is determined. Closed, and every member names a DIFFERENT
# evidential situation — a reader that cannot tell "this row predates the
# record" from "the transcript could not be fetched" cannot tell a backfill gap
# from a storage fault.
REASON_NOT_PERSISTED = "execution_record_not_persisted"
REASON_NO_VERDICT = "no_effect_verdict_on_the_claim"
REASON_VERDICT_NOT_LOCATED = "effect_verdict_row_not_located"
REASON_TRANSCRIPT_UNSTORED = "transcript_unstored"
REASON_STORAGE_KEY_MISSING = "storage_key_missing"
REASON_FETCH_FAILED = "fetch_failed"
REASON_PTR_UNRESOLVABLE = "ptr_unresolvable"
NOT_DETERMINED_REASONS = (
    REASON_NOT_PERSISTED,
    REASON_NO_VERDICT,
    REASON_VERDICT_NOT_LOCATED,
    REASON_TRANSCRIPT_UNSTORED,
    REASON_STORAGE_KEY_MISSING,
    REASON_FETCH_FAILED,
    REASON_PTR_UNRESOLVABLE,
)

# What each reason MEANS, one sentence per reason, because a single sentence for
# all seven would be a data-claim that is false on most of them. The pattern is
# the one C15/F7 measures: a string DESCRIBING what a field means may be constant
# (it is documentation), a string making a claim ABOUT THE ROW's data must be
# derived, because it can be false for the row carrying it. "The execution exists
# in the transcript the pointer names" is a claim about the row, and it is false
# for every reason below whose row has no transcript to name.
#
# Each sentence is written to be true of EVERY row that can carry it — including
# what it does NOT assert, which is the half that matters here: none of them says
# a call was absent, and none of them says a pointer resolves.
_REASON_READINGS = {
    REASON_NOT_PERSISTED: (
        "the verdict this figure was read from carries no stored execution record, so the call that "
        "proved it is not_determined here. It is not a claim that no call was made: the probe ran "
        "and its verdict stands, and what is missing is the record of WHICH call — that record is "
        "written at production time and was never written for this row"
    ),
    REASON_NO_VERDICT: (
        "no effect verdict is attached to this claim at all, so there is no probe execution to name "
        "and no transcript to look in. The claim rests on some other witness, and nothing here says "
        "a call was simulated for it"
    ),
    REASON_VERDICT_NOT_LOCATED: (
        "the claim names an effect verdict this fold could not find, so neither the execution nor "
        "the verdict row behind the figure could be read. The identifier is published beside this "
        "so the mismatch can be checked rather than taken on the fold's word"
    ),
    REASON_TRANSCRIPT_UNSTORED: (
        "the probe ran but its transcript was never stored, so no replayable record of the call "
        "exists to name and none can be recovered later"
    ),
    REASON_STORAGE_KEY_MISSING: (
        "the transcript is registered but carries no storage key, so its body cannot be located. "
        "The call was made and its record is not reachable from here"
    ),
    REASON_FETCH_FAILED: (
        "the transcript's body could not be fetched. This is a transport failure and not a "
        "statement about the call: a later read may recover the same record intact"
    ),
    REASON_PTR_UNRESOLVABLE: (
        "the transcript pointer does not resolve to a stored artifact, so the call that proved this "
        "figure cannot be reached from the pointer the verdict carries"
    ),
}

# Appended only where it is TRUE — a pointer was carried through. On the
# backfill-gap reason the transcript really does hold the execution, and saying
# so is what turns a gap into something a reader can close; on a row with no
# pointer the same sentence would name a transcript that is not there.
_POINTER_CLAUSE = (
    ". The transcript_ptr beside this names the stored transcript the execution was recorded in, "
    "so the call is recoverable by reading it"
)

# A field-description, true of every carrier by construction: it says what a
# consumer may not conclude, and asserts nothing about the row.
_ABSENCE_CLAUSE = (
    ". A consumer must not read this absence as an unseeded probe, as an absent caller, or as a route that matches"
)

# The third state of the two seeding qualifiers. Spelled, never ``None``: a
# ``None`` in a JSON payload is one ``or False`` away from reading as an earned
# negative.
SEEDING_NOT_DETERMINED = "not_determined"


def undetermined_reading(reason: str, transcript_ptr: str | None) -> str:
    """The reading for one undetermined record, derived from its own reason.

    Three parts, and only the middle one is conditional: what this reason means,
    the pointer clause where a pointer was actually carried, and the invariant a
    consumer must not violate. An unregistered reason cannot reach here —
    :meth:`ProvingExecution.__post_init__` rejects it — so there is no default
    sentence standing in for a fact nobody stated.
    """
    body = _REASON_READINGS[reason]
    pointer = _POINTER_CLAUSE if reason == REASON_NOT_PERSISTED and transcript_ptr else ""
    return body + pointer + _ABSENCE_CLAUSE


# The route comparison's three states. ``route_match`` and ``route_mismatch``
# are each earned from a record; with no record neither is, and there is no
# fall-through arm.
ROUTE_MATCH = "route_match"
ROUTE_MISMATCH = "route_mismatch"
ROUTE_NOT_DETERMINED = "not_determined"
ROUTE_VERDICTS = (ROUTE_MATCH, ROUTE_MISMATCH, ROUTE_NOT_DETERMINED)


def _selector_of(calldata: str | None) -> str | None:
    """The 4-byte selector, or ``None`` when the calldata is too short to hold
    one. Never a padded or truncated guess."""
    if not isinstance(calldata, str) or not calldata.startswith("0x") or len(calldata) < 10:
        return None
    return calldata[:10].lower()


def _seeding(value: Any) -> bool | str:
    """A seeding qualifier as its three states. Anything that is not a real
    boolean is the third state — an absent key and a malformed one are both
    "this was not established", and neither may read as ``False``."""
    return value if isinstance(value, bool) else SEEDING_NOT_DETERMINED


@dataclass(frozen=True)
class ProvingExecution:
    """One magnitude's proving execution, or the typed reason there is none.

    Every field outside ``state``/``reason`` is populated only in the
    ``recorded`` state. ``reason`` is populated only in the ``not_determined``
    one. The pairing is checked in ``__post_init__`` so a block cannot claim a
    caller it has no record of, and cannot go undetermined without saying why.

    ``transcript_ptr`` and ``effect_verdict_id`` are the exception and ride in
    BOTH states: they are the row's own identity, read off ``effect_verdicts``
    rather than out of the record, and they are exactly what a reader needs in
    order to go and look when the record itself is missing.
    """

    state: str
    reason: str | None = None
    transcript_ptr: str | None = None
    effect_verdict_id: int | None = None
    caller: str | None = None
    target: str | None = None
    selector: str | None = None
    calldata: str | None = None
    probe_label: str | None = None
    succeeded: bool | None = None
    block_number: int | None = None
    block_source: str | None = None
    chain_id: int | None = None
    tier: str | None = None
    input_seeded: bool | str = SEEDING_NOT_DETERMINED
    contract_balance_seeded: bool | str = SEEDING_NOT_DETERMINED

    def __post_init__(self) -> None:
        if self.state == EXECUTION_RECORDED:
            if self.reason is not None:
                raise ValueError("a recorded execution carries no not_determined reason")
        elif self.state == EXECUTION_NOT_DETERMINED:
            if self.reason not in NOT_DETERMINED_REASONS:
                raise ValueError(f"an undetermined execution must name a registered reason, got {self.reason!r}")
        else:
            raise ValueError(f"unknown execution record state {self.state!r}")

    @property
    def is_recorded(self) -> bool:
        return self.state == EXECUTION_RECORDED

    def as_json(self) -> dict[str, Any]:
        """The published block.

        The undetermined form is deliberately SHORT — state, reason and the two
        pointers — rather than the full field list with nulls in it. A block of
        nulls reads as an execution whose every field came back empty, which is
        a stronger and false claim about how far the lookup got.

        Its ``reading`` is DERIVED from the reason (:func:`undetermined_reading`)
        and not a constant. One sentence for all seven reasons would be a claim
        about the row that is false on most of them — "the execution exists in
        the transcript the pointer names" is not true of a row that has no
        verdict and therefore no pointer — which is the authored-string defect
        class this record exists on the other side of.
        """
        if not self.is_recorded:
            return {
                "state": self.state,
                "reason": self.reason,
                "transcript_ptr": self.transcript_ptr,
                "effect_verdict_id": self.effect_verdict_id,
                "reading": undetermined_reading(cast(str, self.reason), self.transcript_ptr),
            }
        return {
            "state": self.state,
            "transcript_ptr": self.transcript_ptr,
            "effect_verdict_id": self.effect_verdict_id,
            "caller": self.caller,
            "target": self.target,
            "selector": self.selector,
            # Raw, always. See the module docstring: a decoded argument list is
            # honest only against the destination selector's own stored ABI
            # signature, and is a separate question from this one.
            "calldata": self.calldata,
            "arguments_decoded": None,
            "probe_label": self.probe_label,
            "succeeded": self.succeeded,
            "block_number": self.block_number,
            "block_source": self.block_source,
            "chain_id": self.chain_id,
            "tier": self.tier,
            # Three-state, and the third state is spelled. Neither is a boolean
            # a consumer may default to False.
            "input_seeded": self.input_seeded,
            "contract_balance_seeded": self.contract_balance_seeded,
            "reading": (
                "the call this figure's verdict was read off, as the probe issued it: caller is "
                "the impersonated msg.sender, target and selector are what it called, and "
                "calldata is the bytes verbatim and undecoded. input_seeded and "
                "contract_balance_seeded are three-valued and both WEAKEN the figure where they "
                "are true — the first means the caller was given the asset the function pulls, "
                "the second that the target contract's own balance was overridden before the "
                "payout, so the verdict proves a capability of the code rather than an outflow "
                "of present treasury"
            ),
        }


def not_determined(
    reason: str,
    *,
    transcript_ptr: str | None = None,
    effect_verdict_id: int | None = None,
) -> ProvingExecution:
    """The undetermined record, with its reason. Spelled at every call site so
    an unread execution is greppable."""
    return ProvingExecution(
        state=EXECUTION_NOT_DETERMINED,
        reason=reason,
        transcript_ptr=transcript_ptr,
        effect_verdict_id=effect_verdict_id,
    )


def residue_payload(
    *,
    caller: str | None,
    target: str,
    calldata: str,
    probe_label: str,
    succeeded: bool,
    block_number: Any,
    block_source: Any,
    chain_id: Any,
    tier: str,
    input_seeded: bool,
    contract_balance_seeded: bool,
) -> dict[str, Any]:
    """The producer-side payload, JSON-ready for ``observed_residue``.

    Written from the call the recipe ACTUALLY ISSUED — the seeded retry where
    one landed, the unseeded probe where it did not — never from the arguments
    the recipe was asked for. The two differ exactly where it matters: on a
    seeded retry the unseeded call reverted, and recording it would name an
    execution that proved nothing.

    ``block_number`` / ``block_source`` are copied only when the transcript
    certified the height (:func:`services.effects.harness.new_transcript` writes
    ``block_source`` only for a positive, named pin). An uncertified height is
    dropped rather than published: a bystander height read as the observation's
    is the same over-claim one field over.
    """
    pinned = isinstance(block_source, str) and isinstance(block_number, int) and not isinstance(block_number, bool)
    return {
        "caller": caller.lower() if isinstance(caller, str) else None,
        "target": target.lower(),
        "selector": _selector_of(calldata),
        "calldata": calldata,
        "probe_label": probe_label,
        "succeeded": bool(succeeded),
        "block_number": block_number if pinned else None,
        "block_source": block_source if pinned else None,
        "chain_id": chain_id if isinstance(chain_id, int) and not isinstance(chain_id, bool) else None,
        "tier": tier,
        "input_seeded": bool(input_seeded),
        "contract_balance_seeded": bool(contract_balance_seeded),
    }


def from_residue(
    payload: Any,
    *,
    transcript_ptr: str | None,
    effect_verdict_id: int | None,
) -> ProvingExecution:
    """The consumer-side read. A payload that is not a dict is an absent record,
    not an empty one — and ``target``/``calldata`` are REQUIRED, because a
    record naming no call is not a record of an execution."""
    if not isinstance(payload, dict):
        return not_determined(REASON_NOT_PERSISTED, transcript_ptr=transcript_ptr, effect_verdict_id=effect_verdict_id)
    target = payload.get("target")
    calldata = payload.get("calldata")
    if not isinstance(target, str) or not isinstance(calldata, str):
        return not_determined(REASON_NOT_PERSISTED, transcript_ptr=transcript_ptr, effect_verdict_id=effect_verdict_id)
    caller = payload.get("caller")
    succeeded = payload.get("succeeded")
    return ProvingExecution(
        state=EXECUTION_RECORDED,
        transcript_ptr=transcript_ptr,
        effect_verdict_id=effect_verdict_id,
        caller=caller if isinstance(caller, str) else None,
        target=target,
        # Re-derived from the bytes rather than trusted from the payload: the
        # selector IS the first four bytes, and a stored disagreement is a
        # producer bug that must not travel.
        selector=_selector_of(calldata),
        calldata=calldata,
        probe_label=payload.get("probe_label") if isinstance(payload.get("probe_label"), str) else None,
        succeeded=succeeded if isinstance(succeeded, bool) else None,
        block_number=payload.get("block_number") if isinstance(payload.get("block_number"), int) else None,
        block_source=payload.get("block_source") if isinstance(payload.get("block_source"), str) else None,
        chain_id=payload.get("chain_id") if isinstance(payload.get("chain_id"), int) else None,
        tier=payload.get("tier") if isinstance(payload.get("tier"), str) else None,
        input_seeded=_seeding(payload.get("input_seeded")),
        contract_balance_seeded=_seeding(payload.get("contract_balance_seeded")),
    )


def route_comparison(
    execution: ProvingExecution,
    *,
    claimed_caller: str | None,
    claimed_target: str | None,
    claimed_selector: str | None,
) -> dict[str, Any]:
    """Whether the published route is the one the probe took.

    Three states and no fall-through: with no execution record nothing is
    compared and the verdict is ``not_determined`` — never ``route_match`` on
    the grounds that no mismatch was found. The three booleans are three-valued
    for the same reason and go ``None`` where either side is missing.

    Addresses are compared on their bare form: the claimed side is chain-scoped
    (``<chain>::<address>``) and the recorded side is the raw address the probe
    called, so comparing them verbatim would report a mismatch on every row.
    """
    if not execution.is_recorded:
        return {
            "verdict": ROUTE_NOT_DETERMINED,
            "claimed_caller": claimed_caller,
            "claimed_target": claimed_target,
            "claimed_calling_selector": claimed_selector,
            "caller_matches": None,
            "target_matches": None,
            "selector_matches": None,
            "reading": (
                "no execution record reached this entry, so the claimed route was compared "
                "against nothing. This is not a match and not a mismatch"
            ),
        }
    caller_matches = _addr_matches(claimed_caller, execution.caller)
    target_matches = _addr_matches(claimed_target, execution.target)
    selector_matches = (
        None
        if not isinstance(claimed_selector, str) or execution.selector is None
        else claimed_selector.lower() == execution.selector
    )
    matched = (caller_matches, target_matches, selector_matches)
    if any(m is None for m in matched):
        verdict = ROUTE_NOT_DETERMINED
    elif all(matched):
        verdict = ROUTE_MATCH
    else:
        verdict = ROUTE_MISMATCH
    return {
        "verdict": verdict,
        "claimed_caller": claimed_caller,
        "claimed_target": claimed_target,
        "claimed_calling_selector": claimed_selector,
        "caller_matches": caller_matches,
        "target_matches": target_matches,
        "selector_matches": selector_matches,
        "reading": (
            "the route this entry publishes, compared against the call the probe actually "
            "issued. A mismatch does not retract the figure by itself — it says the published "
            "path is not the one the proof took, and what that costs the figure is a separate "
            "ruling. A null conjunct is a comparison that could not be made, never one that passed"
        ),
    }


def _addr_matches(claimed: str | None, recorded: str | None) -> bool | None:
    if not isinstance(claimed, str) or not isinstance(recorded, str):
        return None
    return claimed.rpartition("::")[2].lower() == recorded.rpartition("::")[2].lower()
