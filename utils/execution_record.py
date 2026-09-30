"""The execution that proved a magnitude: one closed shape shared by the producer (``services.effects.recipes`` ->
``observed_residue``) and the consumer (``services.scoring.distill``).

State plane only: the record must never enter ``effect_behavior_cache`` (keyed without address), or a cache hit would
republish another deployment's caller as proof.

An absent record reads as :data:`REASON_NOT_PERSISTED`, and absent seeding keys as :data:`SEEDING_NOT_DETERMINED`, never
as "no caller" or ``False``.

``calldata`` is published raw: decoding is only honest against the destination's own ABI.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

# One string so the two ends can't desynchronize.
PROVING_EXECUTION_KEY = "proving_execution"

EXECUTION_RECORDED = "recorded"
EXECUTION_NOT_DETERMINED = "not_determined"

# The gate's answer to "does a persisted record exist", which the distiller can always answer. Kept separate from the
# record's own states: "none exists" is not "unknown".
GATE_STATE_RECORDED = EXECUTION_RECORDED
GATE_STATE_NOT_RECORDED = "not_recorded"
GATE_STATES = (GATE_STATE_RECORDED, GATE_STATE_NOT_RECORDED)

# Closed; each member names a different evidential situation (a backfill gap vs a storage fault).
REASON_NOT_PERSISTED = "execution_record_not_persisted"
REASON_NO_VERDICT = "no_effect_verdict_on_the_claim"
REASON_VERDICT_NOT_LOCATED = "effect_verdict_row_not_located"
REASON_TRANSCRIPT_UNSTORED = "transcript_unstored"
REASON_STORAGE_KEY_MISSING = "storage_key_missing"
REASON_FETCH_FAILED = "fetch_failed"
REASON_PTR_UNRESOLVABLE = "ptr_unresolvable"
REASON_NO_PROVING_CALL = "transcript_names_no_proving_call"
# Not a gap but the shape of the evidence: the figure is a balance observation, never a call's magnitude.
REASON_NOT_PROVEN_BY_A_CALL = "magnitude_not_proven_by_a_call"
NOT_DETERMINED_REASONS = (
    REASON_NOT_PERSISTED,
    REASON_NO_VERDICT,
    REASON_VERDICT_NOT_LOCATED,
    REASON_TRANSCRIPT_UNSTORED,
    REASON_STORAGE_KEY_MISSING,
    REASON_FETCH_FAILED,
    REASON_PTR_UNRESOLVABLE,
    REASON_NO_PROVING_CALL,
    REASON_NOT_PROVEN_BY_A_CALL,
)

# Faults reaching the evidence; "no execution, no figure" applies only to these. Applied to every reason it would
# withhold every composed figure in the corpus (all predate the record), including the real $44.35M finding.
FAULT_REASONS = (
    REASON_TRANSCRIPT_UNSTORED,
    REASON_STORAGE_KEY_MISSING,
    REASON_FETCH_FAILED,
    REASON_PTR_UNRESOLVABLE,
)

# Per-reason readings: a sentence claiming something about the row must be true of every row carrying that reason.
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
    REASON_NO_PROVING_CALL: (
        "the transcript was read and names no call this reader can identify as the one the figure "
        "was read off. The probe ran and its record is intact; what is not determined is which of "
        "the recorded calls is the proving one, and guessing among them would name an execution "
        "the verdict never rested on"
    ),
    REASON_NOT_PROVEN_BY_A_CALL: (
        "no call proved this figure and none was looked for: the witness is a BALANCE OBSERVATION "
        "of the entity's own sheet, read at the entity and not at a call. There is no probe here "
        "whose transcript could be read, so this absence is the shape of the proof and not a gap "
        "in it. What stands in for a transcript is published beside the figure — the per-asset "
        "dollars at the canonical key, and the assets observed there that nobody priced — and "
        "that is the whole of it: the caller, the block and the observing account are reduced away "
        "when the sheet is loaded, so none of them is claimed here"
    ),
}

# Appended only where a pointer was actually carried.
_POINTER_CLAUSE = (
    ". The transcript_ptr beside this names the stored transcript the execution was recorded in, "
    "so the call is recoverable by reading it"
)

_ABSENCE_CLAUSE = (
    ". A consumer must not read this absence as an unseeded probe, as an absent caller, or as a route that matches"
)

# Spelled, never ``None``: ``None`` is one ``or False`` from an earned negative.
SEEDING_NOT_DETERMINED = "not_determined"


def undetermined_reading(reason: str, transcript_ptr: str | None) -> str:
    """Reason meaning, pointer clause if a pointer was carried, then the consumer invariant."""
    body = _REASON_READINGS[reason]
    pointer = _POINTER_CLAUSE if reason == REASON_NOT_PERSISTED and transcript_ptr else ""
    return body + pointer + _ABSENCE_CLAUSE


# No record means neither match nor mismatch was earned.
ROUTE_MATCH = "route_match"
ROUTE_MISMATCH = "route_mismatch"
ROUTE_NOT_DETERMINED = "not_determined"
ROUTE_VERDICTS = (ROUTE_MATCH, ROUTE_MISMATCH, ROUTE_NOT_DETERMINED)


def _selector_of(calldata: str | None) -> str | None:
    """The 4-byte selector, or ``None`` when calldata is too short. Never padded."""
    if not isinstance(calldata, str) or not calldata.startswith("0x") or len(calldata) < 10:
        return None
    return calldata[:10].lower()


def _seeding(value: Any) -> bool | str:
    """Anything but a real bool is the third state."""
    return value if isinstance(value, bool) else SEEDING_NOT_DETERMINED


@dataclass(frozen=True)
class ProvingExecution:
    """One magnitude's proving execution, or the typed reason there is none.

    ``__post_init__`` checks the pairing. ``transcript_ptr`` and ``effect_verdict_id`` ride in both states: they are
    what a reader needs to go look.
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

        The undetermined form is short: a block of nulls would falsely claim the lookup got that far.
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
            # Raw, always (see the module docstring).
            "calldata": self.calldata,
            "arguments_decoded": None,
            "probe_label": self.probe_label,
            "succeeded": self.succeeded,
            "block_number": self.block_number,
            "block_source": self.block_source,
            "chain_id": self.chain_id,
            "tier": self.tier,
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
    """Spelled at each call site so an unread execution is greppable."""
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
    """The producer-side payload for ``observed_residue``, from the call the recipe actually issued (the seeded retry
    if it landed). The block is copied only when the transcript certified the height.
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
    """A non-dict is an absent record; ``target``/``calldata`` are required."""
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
        # Re-derived from the bytes: a stored disagreement is a producer bug.
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


# ``"{job_id}::{artifact_name}"`` (``workers/effects_worker.py``).
_POINTER_SEPARATOR = "::"

# The producer's own labels: at most one seeded attempt is recorded ``executed``.
_BASE_PROBE_LABEL = "value_probe"
_SEED_OUTCOME_EXECUTED = "executed"


def pointer_parts(transcript_ptr: Any) -> tuple[str, str] | None:
    if not isinstance(transcript_ptr, str):
        return None
    job_id, separator, name = transcript_ptr.partition(_POINTER_SEPARATOR)
    if not separator or not job_id or not name:
        return None
    return job_id, name


def from_transcript(
    blob: Any,
    *,
    transcript_ptr: str | None,
    effect_verdict_id: int | None,
) -> ProvingExecution:
    """Recover the record from the transcript for verdicts that predate it.

    The proving call follows the producer's markers: the seeded attempt recorded ``executed``, else the unseeded
    ``value_probe``; otherwise it's unidentifiable (never guess largest/last/first). Seeding qualifiers follow from that
    choice; ``contract_balance_seeded`` is ``not_determined`` when the transcript doesn't say.
    """
    if not isinstance(blob, dict):
        return not_determined(REASON_FETCH_FAILED, transcript_ptr=transcript_ptr, effect_verdict_id=effect_verdict_id)
    calls = blob.get("calls")
    results = blob.get("results")
    if not isinstance(calls, list) or not isinstance(results, list):
        return not_determined(
            REASON_NO_PROVING_CALL, transcript_ptr=transcript_ptr, effect_verdict_id=effect_verdict_id
        )
    index = _proving_call_index(blob, calls)
    if index is None:
        return not_determined(
            REASON_NO_PROVING_CALL, transcript_ptr=transcript_ptr, effect_verdict_id=effect_verdict_id
        )
    call = calls[index]
    target = call.get("to")
    calldata = call.get("data")
    if not isinstance(target, str) or not isinstance(calldata, str):
        return not_determined(
            REASON_NO_PROVING_CALL, transcript_ptr=transcript_ptr, effect_verdict_id=effect_verdict_id
        )
    result = results[index] if index < len(results) and isinstance(results[index], dict) else {}
    caller = call.get("from")
    seeded = call.get("label") != _BASE_PROBE_LABEL
    balance_seeded: bool | str
    if not seeded:
        # The unseeded probe proved it, so both negatives are earned.
        balance_seeded = False
    else:
        balance_seeded = _seeding(blob.get("contract_balance_seeded"))
    return ProvingExecution(
        state=EXECUTION_RECORDED,
        transcript_ptr=transcript_ptr,
        effect_verdict_id=effect_verdict_id,
        caller=caller.lower() if isinstance(caller, str) else None,
        target=target.lower(),
        selector=_selector_of(calldata),
        calldata=calldata,
        probe_label=call.get("label") if isinstance(call.get("label"), str) else None,
        succeeded=result.get("success") if isinstance(result.get("success"), bool) else None,
        block_number=_pinned_height(blob),
        block_source=blob.get("block_source") if isinstance(blob.get("block_source"), str) else None,
        chain_id=blob.get("chain_id") if isinstance(blob.get("chain_id"), int) else None,
        tier=blob.get("tier") if isinstance(blob.get("tier"), str) else None,
        input_seeded=seeded,
        contract_balance_seeded=balance_seeded,
    )


def _pinned_height(blob: dict[str, Any]) -> int | None:
    """Only a certified height (``block_source`` present); mirrors :func:`residue_payload`."""
    source = blob.get("block_source")
    height = blob.get("block_number")
    if not isinstance(source, str) or not isinstance(height, int) or isinstance(height, bool):
        return None
    return height


def _proving_call_index(blob: dict[str, Any], calls: list[Any]) -> int | None:
    landed = None
    for attempt in blob.get("seed_attempts") or []:
        if isinstance(attempt, dict) and attempt.get("outcome") == _SEED_OUTCOME_EXECUTED:
            landed = attempt.get("label")
    label = landed if isinstance(landed, str) else _BASE_PROBE_LABEL
    # The target call is the last under its label.
    for index in range(len(calls) - 1, -1, -1):
        call = calls[index]
        if isinstance(call, dict) and call.get("label") == label:
            return index
    return None


def route_comparison(
    execution: ProvingExecution,
    *,
    claimed_caller: str | None,
    claimed_target: str | None,
    claimed_selector: str | None,
) -> dict[str, Any]:
    """Whether the published route is the one the probe took.

    No record means ``not_determined``, never a match by absence. Addresses compare bare: the claimed side is
    chain-scoped.
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


# §7.2 arm 1: gate claims transfer on CALLER match; routing is irrelevant because ``isAuthorized(msg.sender, msg.sig)``
# reads no argument, but it reads the caller, so an execution for X proves the gate for X only.
#
# A mismatch doesn't retract the act-as chain (it stands on its own witness); it removes the corroboration, and the
# outcome says so.
GATE_CLAIM_CORROBORATED = "corroborated"
GATE_CLAIM_NOT_CORROBORATED = "not_corroborated"
GATE_CLAIM_NOT_DETERMINED = "not_determined"
GATE_CLAIM_STATES = (GATE_CLAIM_CORROBORATED, GATE_CLAIM_NOT_CORROBORATED, GATE_CLAIM_NOT_DETERMINED)

GATE_CLAIM_REASON_SAME_CALLER = "the_proving_execution_was_admitted_for_the_caller_this_entry_claims"
GATE_CLAIM_REASON_OTHER_CALLER = "the_proving_execution_was_admitted_for_a_different_caller"
GATE_CLAIM_REASON_NOT_COMPARED = "no_execution_record_reached_this_entry_to_compare_a_caller_against"

_GATE_CLAIM_INVARIANT = (
    " The act-as chain beside this is the ACT-AS PLANE's own witness and is not retracted by "
    "anything here: this block says only what the proving execution adds to it."
)


def gate_claim(execution: ProvingExecution, *, claimed_caller: str | None) -> dict[str, Any]:
    """Whether the proving execution corroborates this entry's caller. A mismatch names both addresses."""
    matches = _addr_matches(claimed_caller, execution.caller)
    if matches is None:
        return {
            "state": GATE_CLAIM_NOT_DETERMINED,
            "reason": GATE_CLAIM_REASON_NOT_COMPARED,
            "claimed_caller": claimed_caller,
            "proven_caller": execution.caller,
            "reading": (
                "no caller could be compared: either no execution record reached this entry or it "
                "names no caller, so whether the destination admitted THIS caller is not "
                "determined here. It is not a match and not a mismatch." + _GATE_CLAIM_INVARIANT
            ),
        }
    if matches:
        return {
            "state": GATE_CLAIM_CORROBORATED,
            "reason": GATE_CLAIM_REASON_SAME_CALLER,
            "claimed_caller": claimed_caller,
            "proven_caller": execution.caller,
            "reading": (
                f"the probe was admitted at the destination as {execution.caller}, which is the "
                "caller this entry's last act-as step names, so the destination's authorization "
                "check was exercised for the very address the chain claims. The route it took to "
                "get there differs and is irrelevant to this: an authorization check reads "
                "msg.sender and msg.sig and no argument." + _GATE_CLAIM_INVARIANT
            ),
        }
    return {
        "state": GATE_CLAIM_NOT_CORROBORATED,
        "reason": GATE_CLAIM_REASON_OTHER_CALLER,
        "claimed_caller": claimed_caller,
        "proven_caller": execution.caller,
        "reading": (
            f"the probe was admitted at the destination as {execution.caller}, and this entry's "
            f"last act-as step names {claimed_caller}. The execution therefore establishes the "
            "destination's authorization check for the address it impersonated and for no other — "
            "msg.sender is exactly what that check reads, so the argument that routing is "
            "irrelevant does not carry across a caller it never used. The chain's own claim about "
            "this caller rests on the act-as witness alone and is UNCORROBORATED by any execution "
            "here." + _GATE_CLAIM_INVARIANT
        ),
    }


def _addr_matches(claimed: str | None, recorded: str | None) -> bool | None:
    if not isinstance(claimed, str) or not isinstance(recorded, str):
        return None
    return claimed.rpartition("::")[2].lower() == recorded.rpartition("::")[2].lower()
