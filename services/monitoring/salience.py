"""Salience: does an operator need to see this event.

Orthogonal to ``witness_tier`` (how proven a claim is): a first ``Initialized`` is proven and routine, a polled
``isPaused`` change is weaker and an emergency. ``not_determined`` renders like ``notable``, because defaulting to
``routine`` would suppress on ignorance. Every level carries a non-empty basis from the closed vocabulary below, and no
``routine`` is minted from an absent input.

Assigned per occurrence at runtime. For enrichable types it is provisional: ``enrichment.enrich_events`` re-runs it
before commit.
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

# ``not_determined`` sorts with ``notable`` so thresholds never hide unrated events. Mirrored in
# ``notifier._SALIENCE_ORDER`` and ``site/src/surface/sidebar/activity/eventClass.js``.
SALIENCE_ORDER: dict[str, int] = {
    SALIENCE_ROUTINE: 0,
    SALIENCE_NOT_DETERMINED: 1,
    SALIENCE_NOTABLE: 1,
    SALIENCE_ALERT: 2,
}


def salience_rank(level: str | None) -> int:
    """Rank of *level*; unknown levels rank as ``not_determined``, never ``routine``."""
    return SALIENCE_ORDER.get(level or "", SALIENCE_ORDER[SALIENCE_NOT_DETERMINED])


def max_salience(first: str | None, *rest: str | None) -> str:
    """The strongest level; ties with ``not_determined`` resolve to ``notable`` only if one is present.

    Requires at least one level: an empty fold would have to seed ``routine``. Pass your own floor first, e.g.
    ``max_salience(SALIENCE_NOTABLE, *xs)``.
    """
    best = SALIENCE_ROUTINE
    for level in (first, *rest):
        candidate = level if level in SALIENCE_VALUES else SALIENCE_NOT_DETERMINED
        if salience_rank(candidate) > salience_rank(best):
            best = candidate
        elif salience_rank(candidate) == salience_rank(best) and candidate == SALIENCE_NOTABLE:
            best = SALIENCE_NOTABLE
    return best


# Closed basis vocabulary, shared with the enrichment lane and the frontend. Codes are declared here even before their
# producer exists so it can't drift.

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

# ``data`` keys the rules read.
DATA_KEY_SALIENCE = "salience"
DATA_KEY_SALIENCE_BASIS = "salience_basis"
DATA_KEY_SIGNAL_CLASS = "signal_class"
DATA_KEY_SIGNAL_CLASS_BASIS = "signal_class_basis"
DATA_KEY_SAFE_EXEC = "safe_exec"
DATA_KEY_CORRELATED_EVENTS = "correlated_events"


# ``safe_exec.status`` values that change a level.
SAFE_EXEC_STATUS_DECODED = "decoded"
SAFE_EXEC_STATUS_NOT_TOP_LEVEL = "not_top_level_call"
SAFE_EXEC_STATUS_OVER_BUDGET = "over_budget"
SAFE_EXEC_STATUS_ARGS_UNDECODABLE = "args_undecodable"
# Several executions of this Safe share the transaction, so the arguments describe at most one row. Proving which needs
# the nonce/EIP-712 recompute (over budget).
SAFE_EXEC_STATUS_AMBIGUOUS_ATTRIBUTION = "ambiguous_attribution"

# A decoder looked and couldn't attribute a call: ``not_determined`` with an enrichment-gap basis, not ``no_rule``.
_SAFE_EXEC_EXAMINED_UNDECODED = frozenset(
    {
        SAFE_EXEC_STATUS_OVER_BUDGET,
        SAFE_EXEC_STATUS_ARGS_UNDECODABLE,
        SAFE_EXEC_STATUS_AMBIGUOUS_ATTRIBUTION,
    }
)

# A truncated batch would understate the Safe's action; refuse rather than guess.
SAFE_EXEC_BATCH_UNDECODABLE = "undecodable"

# Set by the enricher on a witnessed match with a pinned MultiSend; absence raises the level.
SAFE_EXEC_KEY_MULTISEND_RECOGNIZED = "multisend_recognized"


# Families whose single occurrence is a control-plane change. Unlisted types fall to ``not_determined``, never
# ``routine``.
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

_EXECUTION_FAILURE_TYPES = frozenset({"safe_tx_failed", "safe_module_failed"})

_TIMELOCK_OPERATION_TYPES = frozenset({"timelock_scheduled", "timelock_executed"})

_SAFE_EXEC_TYPE = "safe_tx_executed"
_SAFE_MODULE_EXEC_TYPE = "safe_module_executed"
_INITIALIZED_TYPE = "initialized"
_STATE_CHANGED_POLL_TYPE = "state_changed_poll"

_TRACKED_CONFIG_STEMS = ("state_changed", "controller_changed")


def _has_stem(event_type: str, stem: str) -> bool:
    """Matches ``value_changed:...`` and the bare ``value_changed`` (minted for an empty controller id)."""
    return event_type == stem or event_type.startswith(f"{stem}:")


def _block(data: Mapping[str, Any], key: str) -> Mapping[str, Any] | None:
    value = data.get(key)
    return value if isinstance(value, Mapping) else None


def _has_prior_initialized(session: "Session", mc: "MonitoredContract") -> bool:
    """Whether the contract already published an ``initialized`` row (the only session rule).

    A second ``Initialized`` on an enrolled proxy is a takeover signal.
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
    """Level one decoded MultiSend inner call earns, by the same rules as the outer call, so a wrapping layer can't
    lower a hostile delegatecall.
    """
    if not isinstance(call, Mapping):
        # A non-call entry can't lower the batch below its floor.
        return SALIENCE_NOTABLE
    if call.get("operation") == 1:
        if not call.get(SAFE_EXEC_KEY_MULTISEND_RECOGNIZED):
            return SALIENCE_ALERT
        nested = call.get("batch")
        if isinstance(nested, list):
            return max_salience(SALIENCE_NOTABLE, *(_inner_call_level(entry) for entry in nested))
        # Recognized MultiSend, not expanded (unreachable from the decoder). ``_batch_is_unexamined`` publishes this,
        # since it ties with the ``notable`` floor.
        return SALIENCE_NOT_DETERMINED
    return SALIENCE_NOTABLE


def _batch_is_unexamined(batch: Any) -> bool:
    """Whether any nested entry is a MultiSend whose payload was never expanded."""
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
    """Level from a ``safe_tx_executed`` enrichment block, or ``None`` if it says nothing actionable."""
    status = safe_exec.get("status")

    if status == SAFE_EXEC_STATUS_NOT_TOP_LEVEL:
        # Positive finding: not a direct ``execTransaction`` on this Safe. Collapsed, never dropped.
        return SALIENCE_ROUTINE, [BASIS_SAFE_EXEC_INDIRECT]

    if status in _SAFE_EXEC_EXAMINED_UNDECODED:
        # Budget declined, arguments undecodable, or ambiguous attribution: nothing found, nothing claimed.
        return SALIENCE_NOT_DETERMINED, [BASIS_SAFE_EXEC_NOT_ENRICHED]

    if status != SAFE_EXEC_STATUS_DECODED:
        return None

    operation = safe_exec.get("operation")

    if operation == 1:
        if not safe_exec.get(SAFE_EXEC_KEY_MULTISEND_RECOGNIZED):
            # Unproven MultiSend is the reason to raise, not proof of malice.
            return SALIENCE_ALERT, [BASIS_SAFE_EXEC_DELEGATECALL_UNRECOGNIZED]
        if safe_exec.get("batch_status") == SAFE_EXEC_BATCH_UNDECODABLE:
            return SALIENCE_NOT_DETERMINED, [BASIS_SAFE_EXEC_BATCH_UNDECODABLE]
        batch = safe_exec.get("batch")
        if not isinstance(batch, list):
            # Recognized MultiSend, never examined.
            return SALIENCE_NOT_DETERMINED, [BASIS_SAFE_EXEC_NOT_ENRICHED]
        if _batch_is_unexamined(batch):
            # An unexpanded nested MultiSend; the fold would wrongly return the ``notable`` floor.
            return SALIENCE_NOT_DETERMINED, [BASIS_SAFE_EXEC_MULTISEND, BASIS_SAFE_EXEC_NOT_ENRICHED]
        level = max_salience(SALIENCE_NOTABLE, *(_inner_call_level(call) for call in batch))
        basis = [BASIS_SAFE_EXEC_MULTISEND]
        if level == SALIENCE_ALERT:
            basis.append(BASIS_SAFE_EXEC_DELEGATECALL_UNRECOGNIZED)
        return level, basis

    if operation == 0:
        # Decoded calls are substantive; name resolution is display only.
        return SALIENCE_NOTABLE, [BASIS_SAFE_EXEC_CALL]

    # Operation flag isn't one the Safe ABI defines.
    return None


def _field_diff_salience(data: Mapping[str, Any]) -> tuple[str, list[str]] | None:
    """Level for a poll or verification-read diff from its stamped ``signal_class``; ``None`` when unstamped (older
    plans), falling through to visible ``not_determined``.
    """
    signal_class = data.get(DATA_KEY_SIGNAL_CLASS)
    signal_basis = data.get(DATA_KEY_SIGNAL_CLASS_BASIS)

    if signal_class == SIGNAL_CLASS_CONFIG:
        return SALIENCE_NOTABLE, [BASIS_CONFIG_FIELD_DIFF]

    if signal_class == SIGNAL_CLASS_METRIC:
        # ``metric`` becomes routine only with a stated basis; ``no_gate_provenance`` counts, absence doesn't.
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
    """The level *event_type* and *data* earn, with ordered basis codes.

    First matching rule wins; correlation is then applied as a max. *session* is only used for ``initialized``. No RPC.
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
    if event_type in CANONICAL_CONFIG_FAMILIES:
        return SALIENCE_ALERT, [BASIS_CANONICAL_CONFIG_FAMILY]

    if event_type in _EXECUTION_FAILURE_TYPES:
        return SALIENCE_ALERT, [BASIS_EXECUTION_FAILURE]

    if event_type == _SAFE_MODULE_EXEC_TYPE:
        # Bypassed the signature ceremony; the module's identity alone earns alert.
        return SALIENCE_ALERT, [BASIS_MODULE_BYPASS_EXECUTION]

    if _has_stem(event_type, MEMBER_CHANGED_STEM):
        return SALIENCE_ALERT, [BASIS_QUALIFIED_MEMBER_CHANGE]

    if event_type == _INITIALIZED_TYPE:
        if mc.enrollment_block is not None and _has_prior_initialized(session, mc):
            return SALIENCE_ALERT, [BASIS_REINITIALIZATION]
        # "First initialization is routine" would rest on the absence of a prior row in a short history, so no rule
        # rates it.
        return SALIENCE_NOT_DETERMINED, [BASIS_NO_RULE]

    if event_type == _SAFE_EXEC_TYPE:
        safe_exec = _block(data, DATA_KEY_SAFE_EXEC)
        if safe_exec is None:
            # Enrichment absent or failed; not demoted on ignorance.
            return SALIENCE_NOT_DETERMINED, [BASIS_SAFE_EXEC_NOT_ENRICHED]
        decided = _safe_exec_salience(safe_exec)
        if decided is not None:
            return decided
        return SALIENCE_NOT_DETERMINED, [BASIS_NO_RULE]

    if event_type == _STATE_CHANGED_POLL_TYPE or _has_stem(event_type, VALUE_CHANGED_STEM):
        decided = _field_diff_salience(data)
        if decided is not None:
            return decided
        return SALIENCE_NOT_DETERMINED, [BASIS_NO_RULE]

    if event_type in _TIMELOCK_OPERATION_TYPES:
        return SALIENCE_NOTABLE, [BASIS_TIMELOCK_OPERATION]

    if any(_has_stem(event_type, stem) for stem in _TRACKED_CONFIG_STEMS):
        # A tracked controller's own event stated the write.
        return SALIENCE_NOTABLE, [BASIS_TRACKED_CONFIG_EVENT]

    return SALIENCE_NOT_DETERMINED, [BASIS_NO_RULE]


def _apply_correlation(level: str, basis: list[str], data: Mapping[str, Any]) -> tuple[str, list[str]]:
    """Raise *level* to at least ``notable`` and the strongest same-transaction effect (entries without a level count
    as ``notable``). An empty list is not a negative: the join only covers what is monitored.
    """
    correlated = data.get(DATA_KEY_CORRELATED_EVENTS)
    if not isinstance(correlated, list) or not correlated:
        return level, basis

    effect_levels = [entry.get(DATA_KEY_SALIENCE) for entry in correlated if isinstance(entry, Mapping)]
    raised = max_salience(level, SALIENCE_NOTABLE, *effect_levels)

    if basis == [BASIS_NO_RULE]:
        # Correlation is the rule that rated it.
        return raised, [BASIS_CORRELATED_CAUSE]
    return raised, [*basis, BASIS_CORRELATED_CAUSE]


def stamp_salience(
    session: "Session",
    event: "MonitoredEvent",
    mc: "MonitoredContract",
) -> tuple[str, list[str]]:
    """Assign and write ``salience``/``salience_basis`` onto *event*'s data; idempotent, so enrichment can re-run it."""
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
    """Copy an entry's ``signal_class`` and basis onto mint-time ``data``, both or neither (a class without a basis
    can't mint ``routine``). Unstamped entries stay visible until re-enrollment.
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
