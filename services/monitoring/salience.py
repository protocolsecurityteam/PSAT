"""Salience — does an operator need to SEE this event.

``witness_tier`` (``event_topics.py``) answers *how proven is this claim*.
This module answers the orthogonal question, and the two must never be
collapsed: a ``self_describing`` ``Initialized(uint8)`` is maximally proven
and, on a fresh proxy, maximally routine; a ``state_changed_poll`` on
``isPaused`` is a weaker-provenance row and an emergency.

Four levels, not three. ``not_determined`` is the third-state discipline
applied to this axis — a row written before this landed, or an event type no
rule rated, is unclassified and **renders like ``notable``**. Defaulting an
unclassified event to ``routine`` would be silent suppression minted from
ignorance, which is the failure mode the witness overhaul removed from the
claim plane; it does not get to reappear on the display plane.

Every level ships with a non-empty, ordered ``salience_basis`` drawn from the
closed vocabulary below. The basis is not decoration: it is what makes a level
auditable and what a later rule change can be diffed against. In particular
**no ``routine`` is ever minted from an absent input** — the two routine arms
each rest on a positive finding (a stamped ``signal_class`` with its own
basis; a decoded ``not_top_level_call`` status).

Assignment is runtime and per-occurrence, never enrollment-time: the same
``safe_tx_executed`` type is ``alert`` when it delegatecalls an unrecognized
target and ``routine`` when the observed transaction was not this Safe's own
``execTransaction`` at all. Enrollment cannot know.

For enrichable types the mint-time assignment is **provisional**: the
enrichment driver (``enrichment.enrich_events``) re-runs ``assign_salience``
after an enricher changes the inputs these rules read, inside the same
transaction and before commit/notify.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Mapping

from services.monitoring.event_topics import (
    MEMBER_CHANGED_STEM,
    SIGNAL_CLASS_CONFIG,
    SIGNAL_CLASS_METRIC,
    VALUE_CHANGED_STEM,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from sqlalchemy.orm import Session

    from db.models import MonitoredContract, MonitoredEvent

# ---------------------------------------------------------------------------
# The axis
# ---------------------------------------------------------------------------

SALIENCE_ALERT = "alert"  # notify always; never hidden
SALIENCE_NOTABLE = "notable"  # timeline-visible by default
SALIENCE_ROUTINE = "routine"  # collapsed by default; NEVER deleted, NEVER un-notified by default
SALIENCE_NOT_DETERMINED = "not_determined"  # unclassified — renders as notable, never as routine

SALIENCE_VALUES = frozenset(
    {
        SALIENCE_ALERT,
        SALIENCE_NOTABLE,
        SALIENCE_ROUTINE,
        SALIENCE_NOT_DETERMINED,
    }
)

# Comparison order. ``not_determined`` deliberately sorts WITH ``notable``: an
# event the classifier never rated must not be filtered out by a threshold it
# was never measured against. Mirrored by ``notifier._SALIENCE_ORDER`` and by
# ``site/src/monitoring/format.js``.
SALIENCE_ORDER: dict[str, int] = {
    SALIENCE_ROUTINE: 0,
    SALIENCE_NOT_DETERMINED: 1,
    SALIENCE_NOTABLE: 1,
    SALIENCE_ALERT: 2,
}


def salience_rank(level: str | None) -> int:
    """Order position of *level*, with an unknown/absent level sorting at the
    ``not_determined`` position — never at ``routine``."""
    return SALIENCE_ORDER.get(level or "", SALIENCE_ORDER[SALIENCE_NOT_DETERMINED])


def max_salience(first: str | None, *rest: str | None) -> str:
    """The strongest of the given levels. ``not_determined`` and ``notable``
    share a rank, so ties resolve to ``notable`` — the level that states a
    finding — only when a ``notable`` is actually among the inputs.

    At least one level is REQUIRED. The seed of a max fold over an empty
    sequence would have to be ``routine``, and a ``routine`` returned because
    there was nothing to compare is exactly the minted-from-absence level the
    mechanical gate forbids. A caller with a possibly-empty sequence must
    supply its own floor as *first* (``max_salience(SALIENCE_NOTABLE, *xs)``),
    which states what an empty sequence means rather than defaulting it.
    """
    best = SALIENCE_ROUTINE
    for level in (first, *rest):
        candidate = level if level in SALIENCE_VALUES else SALIENCE_NOT_DETERMINED
        if salience_rank(candidate) > salience_rank(best):
            best = candidate
        elif salience_rank(candidate) == salience_rank(best) and candidate == SALIENCE_NOTABLE:
            best = SALIENCE_NOTABLE
    return best


# ---------------------------------------------------------------------------
# Closed basis vocabulary
# ---------------------------------------------------------------------------
#
# Every code the rules below can emit. The S2 enrichment lane produces the
# inputs for four of them (``safe_exec_call``, ``safe_exec_multisend``,
# ``safe_exec_delegatecall_unrecognized``, ``safe_exec_batch_undecodable``)
# and for ``correlated_cause``; they are declared HERE regardless, because the
# vocabulary is the S1↔S2↔frontend interface and a code that appears only when
# its producer lands is a vocabulary that drifts.

BASIS_CANONICAL_CONFIG_FAMILY = "canonical_config_family"
BASIS_EXECUTION_FAILURE = "execution_failure"
BASIS_SAFE_EXEC_DELEGATECALL_UNRECOGNIZED = "safe_exec_delegatecall_unrecognized"
BASIS_MODULE_BYPASS_EXECUTION = "module_bypass_execution"
BASIS_QUALIFIED_MEMBER_CHANGE = "qualified_member_change"
BASIS_REINITIALIZATION = "reinitialization"
BASIS_CONFIG_FIELD_DIFF = "config_field_diff"
BASIS_TIMELOCK_OPERATION = "timelock_operation"
BASIS_SAFE_EXEC_CALL = "safe_exec_call"
BASIS_SAFE_EXEC_MULTISEND = "safe_exec_multisend"
BASIS_SAFE_EXEC_BATCH_UNDECODABLE = "safe_exec_batch_undecodable"
BASIS_TRACKED_CONFIG_EVENT = "tracked_config_event"
BASIS_CORRELATED_CAUSE = "correlated_cause"
BASIS_METRIC_FIELD_DIFF = "metric_field_diff"
BASIS_SAFE_EXEC_INDIRECT = "safe_exec_indirect"
BASIS_SAFE_EXEC_NOT_ENRICHED = "safe_exec_not_enriched"
BASIS_NO_RULE = "no_rule"

SALIENCE_BASIS_VALUES = frozenset(
    {
        BASIS_CANONICAL_CONFIG_FAMILY,
        BASIS_EXECUTION_FAILURE,
        BASIS_SAFE_EXEC_DELEGATECALL_UNRECOGNIZED,
        BASIS_MODULE_BYPASS_EXECUTION,
        BASIS_QUALIFIED_MEMBER_CHANGE,
        BASIS_REINITIALIZATION,
        BASIS_CONFIG_FIELD_DIFF,
        BASIS_TIMELOCK_OPERATION,
        BASIS_SAFE_EXEC_CALL,
        BASIS_SAFE_EXEC_MULTISEND,
        BASIS_SAFE_EXEC_BATCH_UNDECODABLE,
        BASIS_TRACKED_CONFIG_EVENT,
        BASIS_CORRELATED_CAUSE,
        BASIS_METRIC_FIELD_DIFF,
        BASIS_SAFE_EXEC_INDIRECT,
        BASIS_SAFE_EXEC_NOT_ENRICHED,
        BASIS_NO_RULE,
    }
)

# ``data`` keys these rules read. Named here so the S1↔S2 contract is one
# list rather than a set of string literals scattered through two modules.
DATA_KEY_SALIENCE = "salience"
DATA_KEY_SALIENCE_BASIS = "salience_basis"
DATA_KEY_SIGNAL_CLASS = "signal_class"
DATA_KEY_SIGNAL_CLASS_BASIS = "signal_class_basis"
DATA_KEY_SAFE_EXEC = "safe_exec"
DATA_KEY_CORRELATED_EVENTS = "correlated_events"


# ``safe_exec.status`` values these rules discriminate on. The full set is
# S2's to publish; these are the ones that change a level.
SAFE_EXEC_STATUS_DECODED = "decoded"
SAFE_EXEC_STATUS_NOT_TOP_LEVEL = "not_top_level_call"
SAFE_EXEC_STATUS_OVER_BUDGET = "over_budget"
# A proven ``execTransaction`` whose ARGUMENTS would not decode.
SAFE_EXEC_STATUS_ARGS_UNDECODABLE = "args_undecodable"
# More than one execution of THIS Safe shares the transaction, so the one set
# of top-level arguments describes at most one of the rows and nothing
# witnesses which. Proving it needs the Safe nonce / EIP-712 recompute, which
# is outside this run's RPC budget.
SAFE_EXEC_STATUS_AMBIGUOUS_ATTRIBUTION = "ambiguous_attribution"

# Statuses that state "a decoder looked and could not attribute a call to this
# row". They are findings, not silence — so the level is ``not_determined``
# (visible) and the basis names the enrichment gap rather than falling through
# to ``no_rule``, which would say no rule considered the row at all.
_SAFE_EXEC_EXAMINED_UNDECODED = frozenset(
    {
        SAFE_EXEC_STATUS_OVER_BUDGET,
        SAFE_EXEC_STATUS_ARGS_UNDECODABLE,
        SAFE_EXEC_STATUS_AMBIGUOUS_ATTRIBUTION,
    }
)

# ``safe_exec.batch_status`` when the packed MultiSend payload did not decode.
# A truncated batch would understate what the Safe did, so no partial list is
# published and the level refuses rather than guesses.
SAFE_EXEC_BATCH_UNDECODABLE = "undecodable"

# Set by S2's enricher: did ``safe_exec.to`` (or an inner call's ``to``) equal
# a pinned MultiSend deployment? A witnessed address comparison, so its
# ABSENCE is "not proven to be MultiSend", which is the reason to raise the
# level rather than to lower it.
SAFE_EXEC_KEY_MULTISEND_RECOGNIZED = "multisend_recognized"


# ---------------------------------------------------------------------------
# Rule inputs
# ---------------------------------------------------------------------------

# Hand-rolled families whose single occurrence IS a control-plane change, with
# the moved binding in its own decoded args. Verbatim from §4.2; types outside
# this set are not silently folded in — an unlisted type falls through to
# ``not_determined`` (visible), never to ``routine``.
CANONICAL_CONFIG_FAMILIES = frozenset(
    {
        "upgraded",
        "beacon_upgraded",
        "admin_changed",
        "diamond_cut",
        "new_implementation",
        "changed_master_copy",
        "target_updated",
        "upgraded_revision",
        "ownership_transferred",
        "authority_updated",
        "role_granted",
        "role_revoked",
        "signer_added",
        "signer_removed",
        "threshold_changed",
        "safe_module_enabled",
        "safe_module_disabled",
        "safe_guard_changed",
        "delay_changed",
        "paused",
        "unpaused",
    }
)

# An execution that reverted is an anomaly by construction.
_EXECUTION_FAILURE_TYPES = frozenset({"safe_tx_failed", "safe_module_failed"})

_TIMELOCK_OPERATION_TYPES = frozenset({"timelock_scheduled", "timelock_executed"})

_SAFE_EXEC_TYPE = "safe_tx_executed"
_SAFE_MODULE_EXEC_TYPE = "safe_module_executed"
_INITIALIZED_TYPE = "initialized"
_STATE_CHANGED_POLL_TYPE = "state_changed_poll"

_TRACKED_CONFIG_STEMS = ("state_changed", "controller_changed")


def _has_stem(event_type: str, stem: str) -> bool:
    """``value_changed:state_variable:owner`` and the bare ``value_changed``
    both carry the stem. ``event_topics`` mints the bare form when a
    controller id is empty, so matching the prefix alone would miss it."""
    return event_type == stem or event_type.startswith(f"{stem}:")


def _block(data: Mapping[str, Any], key: str) -> Mapping[str, Any] | None:
    value = data.get(key)
    return value if isinstance(value, Mapping) else None


def _has_prior_initialized(session: "Session", mc: "MonitoredContract") -> bool:
    """Has this contract already published an ``initialized`` row?

    The one rule that needs the session. A second ``Initialized`` on a proxy
    whose enrollment block is known is a takeover signal; the first one is the
    deployment doing what deployments do.
    """
    from sqlalchemy import select

    from db.models import MonitoredEvent

    row = session.execute(
        select(MonitoredEvent.id)
        .where(
            MonitoredEvent.monitored_contract_id == mc.id,
            MonitoredEvent.event_type == _INITIALIZED_TYPE,
        )
        .limit(1)
    ).first()
    return row is not None


def _inner_call_level(call: Any) -> str:
    """Level one decoded MultiSend inner call earns on its own.

    Each inner call is evaluated by the same operation rules as the outer one:
    a delegatecall to a target not proven to be MultiSend is an ``alert``;
    anything else takes the decoded-call floor. A recognized-MultiSend inner
    call is a batch in its own right and folds the same way, so one extra
    wrapping layer cannot lower what a hostile inner delegatecall earns.
    """
    if not isinstance(call, Mapping):
        # A batch entry that is not a decoded call is not a finding about
        # that call; it may not lower the batch below its floor.
        return SALIENCE_NOTABLE
    if call.get("operation") == 1:
        if not call.get(SAFE_EXEC_KEY_MULTISEND_RECOGNIZED):
            return SALIENCE_ALERT
        nested = call.get("batch")
        if isinstance(nested, list):
            return max_salience(SALIENCE_NOTABLE, *(_inner_call_level(entry) for entry in nested))
        # Recognized MultiSend, contents not expanded. Unreachable from the
        # decoder (an unexpandable nested payload takes the WHOLE batch to a
        # stated failure), and rated here anyway: an unexamined batch is not a
        # quiet one. ``_batch_is_unexamined`` is what turns this into the
        # published level; the fold alone could not, because ``not_determined``
        # ties with the ``notable`` floor.
        return SALIENCE_NOT_DETERMINED
    return SALIENCE_NOTABLE


def _batch_is_unexamined(batch: Any) -> bool:
    """Does any entry, at any depth, claim to be a MultiSend whose payload was
    never expanded? Such a batch states a level about calls nobody read."""
    if not isinstance(batch, list):
        return False
    for entry in batch:
        if not isinstance(entry, Mapping) or entry.get("operation") != 1:
            continue
        if not entry.get(SAFE_EXEC_KEY_MULTISEND_RECOGNIZED):
            continue
        nested = entry.get("batch")
        if not isinstance(nested, list) or _batch_is_unexamined(nested):
            return True
    return False


def _safe_exec_salience(safe_exec: Mapping[str, Any]) -> tuple[str, list[str]] | None:
    """Level for a ``safe_tx_executed`` from its enrichment block, or ``None``
    when the block says nothing this axis can act on."""
    status = safe_exec.get("status")

    if status == SAFE_EXEC_STATUS_NOT_TOP_LEVEL:
        # A POSITIVE finding: the observed transaction was proven not to be a
        # direct ``execTransaction`` on this Safe (relayer, nested Safe,
        # wrapper). The row collapses; it is never dropped.
        return SALIENCE_ROUTINE, [BASIS_SAFE_EXEC_INDIRECT]

    if status in _SAFE_EXEC_EXAMINED_UNDECODED:
        # A decoder looked and could not attribute a call to this row — the
        # budget declined it, the arguments would not decode, or two executions
        # of this Safe share the transaction and nothing witnesses which one
        # these arguments describe. Nothing was found, so nothing is claimed,
        # and the basis names the enrichment gap rather than saying no rule
        # considered the row.
        return SALIENCE_NOT_DETERMINED, [BASIS_SAFE_EXEC_NOT_ENRICHED]

    if status != SAFE_EXEC_STATUS_DECODED:
        return None

    operation = safe_exec.get("operation")

    if operation == 1:
        if not safe_exec.get(SAFE_EXEC_KEY_MULTISEND_RECOGNIZED):
            # Not proven to be MultiSend — which is exactly the reason to
            # raise it, not a proof that it is malicious.
            return SALIENCE_ALERT, [BASIS_SAFE_EXEC_DELEGATECALL_UNRECOGNIZED]
        if safe_exec.get("batch_status") == SAFE_EXEC_BATCH_UNDECODABLE:
            return SALIENCE_NOT_DETERMINED, [BASIS_SAFE_EXEC_BATCH_UNDECODABLE]
        batch = safe_exec.get("batch")
        if not isinstance(batch, list):
            # Recognized MultiSend, no expansion and no stated failure: the
            # batch was not examined, so its contents are unknown.
            return SALIENCE_NOT_DETERMINED, [BASIS_SAFE_EXEC_NOT_ENRICHED]
        if _batch_is_unexamined(batch):
            # A nested MultiSend somewhere in the tree was never expanded. The
            # fold below would return the ``notable`` floor for it, which would
            # publish a level about calls nobody read — one wrapping layer is
            # not a reason to trust a payload.
            return SALIENCE_NOT_DETERMINED, [BASIS_SAFE_EXEC_MULTISEND, BASIS_SAFE_EXEC_NOT_ENRICHED]
        level = max_salience(SALIENCE_NOTABLE, *(_inner_call_level(call) for call in batch))
        basis = [BASIS_SAFE_EXEC_MULTISEND]
        if level == SALIENCE_ALERT:
            basis.append(BASIS_SAFE_EXEC_DELEGATECALL_UNRECOGNIZED)
        return level, basis

    if operation == 0:
        # A decoded call is substantive whether or not §3.3 resolves a name.
        # Name resolution affects DISPLAY only: a name is not a witness.
        return SALIENCE_NOTABLE, [BASIS_SAFE_EXEC_CALL]

    # Status says decoded but the operation flag is not one of the two the
    # Safe ABI defines — the decode did not produce what the rules read.
    return None


def _field_diff_salience(data: Mapping[str, Any]) -> tuple[str, list[str]] | None:
    """Level for a poll / verification-read diff, from the ``signal_class``
    the mint site stamped off the polling-plan entry.

    An entry carrying no ``signal_class`` stamps nothing, and this returns
    ``None`` so the row falls through to ``not_determined`` (visible). That is
    the phase-1 steady state for the whole fleet: persisted polling plans
    predate the stamp, and inventing a class for them would be exactly the
    minted-from-absence suppression the mechanical gate forbids.
    """
    signal_class = data.get(DATA_KEY_SIGNAL_CLASS)
    signal_basis = data.get(DATA_KEY_SIGNAL_CLASS_BASIS)

    if signal_class == SIGNAL_CLASS_CONFIG:
        return SALIENCE_NOTABLE, [BASIS_CONFIG_FIELD_DIFF]

    if signal_class == SIGNAL_CLASS_METRIC:
        # The mechanical gate: ``metric ⇒ routine`` only when the plan states
        # WHY. ``no_gate_provenance`` counts (§3.6 ruling — a completed
        # derivation that carries no gate proof is a measured finding), an
        # absent basis does not.
        if isinstance(signal_basis, str) and signal_basis:
            return SALIENCE_ROUTINE, [BASIS_METRIC_FIELD_DIFF]
        return None

    return None


def assign_salience(
    session: "Session",
    event_type: str,
    data: Mapping[str, Any] | None,
    mc: "MonitoredContract",
) -> tuple[str, list[str]]:
    """The level *event_type* + *data* earn, with the ordered basis codes.

    Rules are evaluated in §4.2's order and the first match wins — except
    correlation, which is applied as a MAX over the first match rather than as
    a rule in the chain (§3.4: a correlated cause is at least as salient as
    its effects).

    *session* is used by exactly one rule (``reinitialization``) and only when
    the type is ``initialized``. No rule issues RPC.
    """
    payload: Mapping[str, Any] = data if isinstance(data, Mapping) else {}
    level, basis = _assign_first_match(session, event_type, payload, mc)
    return _apply_correlation(level, basis, payload)


def _assign_first_match(
    session: "Session",
    event_type: str,
    data: Mapping[str, Any],
    mc: "MonitoredContract",
) -> tuple[str, list[str]]:
    # --- alert ------------------------------------------------------------
    if event_type in CANONICAL_CONFIG_FAMILIES:
        return SALIENCE_ALERT, [BASIS_CANONICAL_CONFIG_FAMILY]

    if event_type in _EXECUTION_FAILURE_TYPES:
        return SALIENCE_ALERT, [BASIS_EXECUTION_FAILURE]

    if event_type == _SAFE_MODULE_EXEC_TYPE:
        # An execution that bypassed the signature ceremony. The event
        # witnesses only the module's identity, and that alone earns it.
        return SALIENCE_ALERT, [BASIS_MODULE_BYPASS_EXECUTION]

    if _has_stem(event_type, MEMBER_CHANGED_STEM):
        return SALIENCE_ALERT, [BASIS_QUALIFIED_MEMBER_CHANGE]

    if event_type == _INITIALIZED_TYPE:
        if mc.enrollment_block is not None and _has_prior_initialized(session, mc):
            return SALIENCE_ALERT, [BASIS_REINITIALIZATION]
        # A first initialization on a fresh proxy is maximally proven and
        # maximally routine — but "routine" here would be minted from the
        # ABSENCE of a prior row on a monitoring history days long, so the
        # honest answer is that no rule rated it.
        return SALIENCE_NOT_DETERMINED, [BASIS_NO_RULE]

    # --- the safe_exec arm ------------------------------------------------
    if event_type == _SAFE_EXEC_TYPE:
        safe_exec = _block(data, DATA_KEY_SAFE_EXEC)
        if safe_exec is None:
            # The phase-1 steady state: enrichment absent or failed. A Safe
            # execution we could not examine may not be demoted on ignorance.
            return SALIENCE_NOT_DETERMINED, [BASIS_SAFE_EXEC_NOT_ENRICHED]
        decided = _safe_exec_salience(safe_exec)
        if decided is not None:
            return decided
        return SALIENCE_NOT_DETERMINED, [BASIS_NO_RULE]

    # --- notable / routine field diffs ------------------------------------
    if event_type == _STATE_CHANGED_POLL_TYPE or _has_stem(event_type, VALUE_CHANGED_STEM):
        decided = _field_diff_salience(data)
        if decided is not None:
            return decided
        return SALIENCE_NOT_DETERMINED, [BASIS_NO_RULE]

    if event_type in _TIMELOCK_OPERATION_TYPES:
        return SALIENCE_NOTABLE, [BASIS_TIMELOCK_OPERATION]

    if any(_has_stem(event_type, stem) for stem in _TRACKED_CONFIG_STEMS):
        # The self_describing arm of the per-contract taxonomy: a tracked
        # controller's own event stated the write and qualified to publish.
        return SALIENCE_NOTABLE, [BASIS_TRACKED_CONFIG_EVENT]

    return SALIENCE_NOT_DETERMINED, [BASIS_NO_RULE]


def _apply_correlation(level: str, basis: list[str], data: Mapping[str, Any]) -> tuple[str, list[str]]:
    """Raise *level* to at least ``notable`` and to at least the strongest of
    the effects this event caused in the same transaction.

    Same transaction hash is a fact, not an inference, so both directions are
    witnessed. Each entry may carry the effect's own ``salience`` (S2 writes
    it when it builds the join); an entry without one contributes the
    ``notable`` floor rather than a guess.

    An empty / absent list is NOT an earned negative — the join is scoped to
    what is monitored, which is why S2 publishes ``correlated_scope`` beside
    it — so it changes nothing here.
    """
    correlated = data.get(DATA_KEY_CORRELATED_EVENTS)
    if not isinstance(correlated, list) or not correlated:
        return level, basis

    effect_levels = [entry.get(DATA_KEY_SALIENCE) for entry in correlated if isinstance(entry, Mapping)]
    raised = max_salience(level, SALIENCE_NOTABLE, *effect_levels)

    if basis == [BASIS_NO_RULE]:
        # ``no_rule`` would now be false: correlation IS the rule that rated it.
        return raised, [BASIS_CORRELATED_CAUSE]
    return raised, [*basis, BASIS_CORRELATED_CAUSE]


def stamp_salience(
    session: "Session",
    event: "MonitoredEvent",
    mc: "MonitoredContract",
) -> tuple[str, list[str]]:
    """Assign and write ``salience`` / ``salience_basis`` onto *event*'s data.

    Idempotent and cheap, which is what lets the enrichment driver re-run it
    after an enricher changes the inputs the rules read.
    """
    from sqlalchemy.orm.attributes import flag_modified

    data = event.data if isinstance(event.data, dict) else {}
    level, basis = assign_salience(session, event.event_type, data, mc)
    updated = dict(data)
    updated[DATA_KEY_SALIENCE] = level
    updated[DATA_KEY_SALIENCE_BASIS] = basis
    event.data = updated
    flag_modified(event, "data")
    return level, basis


def stamp_signal_class(data: dict[str, Any], entry: Mapping[str, Any] | None) -> dict[str, Any]:
    """Copy a polling-plan entry's ``signal_class`` + basis onto a mint-time
    ``data`` dict.

    An entry with no ``signal_class`` — every persisted pre-this-change plan —
    stamps NOTHING, so the salience rule falls through to ``not_determined``
    and the row stays visible until a re-enrollment pass re-derives the plan.
    Both keys move together or neither does: a class without its basis cannot
    mint ``routine``, so writing one alone would only produce a row that looks
    classified and is not.
    """
    if not isinstance(entry, Mapping):
        return data
    signal_class = entry.get(DATA_KEY_SIGNAL_CLASS)
    signal_basis = entry.get(DATA_KEY_SIGNAL_CLASS_BASIS)
    if not isinstance(signal_class, str) or not signal_class:
        return data
    if not isinstance(signal_basis, str) or not signal_basis:
        return data
    data[DATA_KEY_SIGNAL_CLASS] = signal_class
    data[DATA_KEY_SIGNAL_CLASS_BASIS] = signal_basis
    return data
