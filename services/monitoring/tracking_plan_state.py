"""The tracking-plan state a ``monitoring_config`` carries: the not-determined tokens, the
staleness merge, and the coverage census.

State is always signalled by a positive token, never by key absence:

===========================  ==============================  ================
``tracked_topics``           ``tracking_plan_not_determined`` state
===========================  ==============================  ================
present                      absent                          ready_fresh
present                      present                         ready_stale
absent                       present                         not_determined
absent                       absent                          unclassified
===========================  ==============================  ================

``ready_stale`` keeps watching on the last plan actually read, stamped with when it stopped
being confirmable; it is neither fresh nor ignorance. ``unclassified`` is a row this builder
never produced.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from sqlalchemy import cast, func, literal, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session

from db.models import ContractMaterialization, MonitoredContract, MonitoringEnrollmentQueue
from utils.chains import chain_cache_token

TRACKED_TOPICS_KEY = "tracked_topics"
NOT_DETERMINED_KEY = "tracking_plan_not_determined"
POLLING_PLAN_KEY = "polling_plan"
# First re-enrollment that could not re-read the plan; topics are last-known-good as of then.
TRACKED_TOPICS_STALE_SINCE_KEY = "tracked_topics_stale_since"
POLLING_PLAN_STALE_SINCE_KEY = "polling_plan_stale_since"
# Block intervals the scanner never covered (operator cursor-clamp tooling); see :func:`preserve_scan_plane_facts`.
SCAN_GAPS_KEY = "scan_gaps"


#: ``find_by_address`` raised.
MATERIALIZATION_LOOKUP_FAILED = "materialization_lookup_failed"
# No row, not ready, or superseded schema version.
NO_CURRENT_MATERIALIZATION = "no_current_materialization"
#: The bucket answered and holds no such object.
PLAN_OBJECT_ABSENT = "plan_object_absent"
#: The bucket could not be asked.
PLAN_NOT_READABLE = "plan_not_readable"
#: The plan was there and would not parse.
PLAN_LOAD_ERROR = "plan_load_error"

#: Enrolled without ever being analyzed (primary controllers).
CONTRACT_NOT_ANALYZED = "contract_not_analyzed"
#: Authored by an API caller; no analyzer provenance at all.
CONFIG_SUPPLIED_BY_CALLER = "config_supplied_by_caller"

# Can recover without new analysis. Corrupt blobs also read as PLAN_NOT_READABLE and share the capped retries.
TRANSIENT_PLAN_FAILURES = frozenset({MATERIALIZATION_LOOKUP_FAILED, PLAN_NOT_READABLE})

# Enrollment deferred because the chain head was undetermined; the queue row carries the deferral and the census counts
# it.
HEAD_NOT_DETERMINED_REASON = "head_not_determined"

PLAN_NOT_DETERMINED_TOKENS = frozenset(
    {
        MATERIALIZATION_LOOKUP_FAILED,
        NO_CURRENT_MATERIALIZATION,
        PLAN_OBJECT_ABSENT,
        PLAN_NOT_READABLE,
        PLAN_LOAD_ERROR,
        CONTRACT_NOT_ANALYZED,
        CONFIG_SUPPLIED_BY_CALLER,
    }
)

# Tokens whose config may inherit the last-read plan. Not caller-authored configs: that would resurrect topics the
# operator just replaced.
STALENESS_MERGE_TOKENS = PLAN_NOT_DETERMINED_TOKENS - {CONFIG_SUPPLIED_BY_CALLER}


READY_FRESH_WITH_TOPICS = "ready_fresh_with_topics"
READY_FRESH_PROVEN_EMPTY = "ready_fresh_proven_empty"
READY_STALE = "ready_stale"
UNCLASSIFIED = "unclassified"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def merge_stale_tracking_plan(
    new_config: dict[str, Any],
    existing_config: Mapping[str, Any] | None,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Re-enrollment's config, with last-known-good watching preserved.

    Without this, a failed plan read would replace witnessed topics with nothing to watch, indistinguishable from "read
    and named nothing". Topics carry forward, stamped stale, only when the new token is in
    :data:`STALENESS_MERGE_TOKENS`, the old config has non-empty topics, and its provenance is an analyzer plan read.
    The polling plan rides along under the same rule.
    """
    token = new_config.get(NOT_DETERMINED_KEY)
    if token not in STALENESS_MERGE_TOKENS:
        return new_config
    if not isinstance(existing_config, Mapping):
        return new_config
    if existing_config.get(NOT_DETERMINED_KEY) == CONFIG_SUPPLIED_BY_CALLER:
        return new_config

    last_good = existing_config.get(TRACKED_TOPICS_KEY)
    if not isinstance(last_good, list) or not last_good:
        return new_config

    stale_since = existing_config.get(TRACKED_TOPICS_STALE_SINCE_KEY)
    if not isinstance(stale_since, str) or not stale_since:
        # A later failure keeps the first instant.
        stale_since = (now or _utcnow()).isoformat()

    merged = dict(new_config)
    merged[TRACKED_TOPICS_KEY] = list(last_good)
    merged[TRACKED_TOPICS_STALE_SINCE_KEY] = stale_since
    # Re-derived: the flag is a function of the watch list.
    if any(isinstance(t, Mapping) and t.get("event_type") == "authority_updated" for t in last_good):
        merged["watch_authority"] = True

    merged_plan = _merge_polling_plan(new_config.get(POLLING_PLAN_KEY), existing_config.get(POLLING_PLAN_KEY))
    if merged_plan is not None:
        # Non-None means entries were carried; comparing lengths would miss malformed entries the merge dropped.
        merged[POLLING_PLAN_KEY] = merged_plan
        merged[POLLING_PLAN_STALE_SINCE_KEY] = existing_config.get(POLLING_PLAN_STALE_SINCE_KEY) or stale_since

    return merged


def preserve_scan_plane_facts(
    new_config: dict[str, Any],
    existing_config: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Carry ``scan_gaps`` onto any rebuilt config, unconditionally: dropping it would claim continuous coverage over
    unread intervals.
    """
    gaps = (existing_config or {}).get(SCAN_GAPS_KEY)
    if not isinstance(gaps, list) or not gaps:
        return new_config
    if new_config.get(SCAN_GAPS_KEY) == gaps:
        return new_config
    return {**new_config, SCAN_GAPS_KEY: gaps}


def _merge_polling_plan(new_plan: Any, existing_plan: Any) -> list[dict] | None:
    """Fresh entries win their field; last-good entries fill fields only a readable plan can name.

    ``None`` if nothing to carry.
    """
    if not isinstance(existing_plan, list) or not existing_plan:
        return None
    fresh = [e for e in (new_plan or []) if isinstance(e, dict)]
    fresh_fields = {e.get("field") for e in fresh}
    carried = [
        e for e in existing_plan if isinstance(e, dict) and e.get("field") and e.get("field") not in fresh_fields
    ]
    if not carried:
        return None
    return fresh + carried


def _state_from_parts(token: Any, has_topics_key: bool, topics_present: bool, has_stale_since: bool) -> str:
    """The module's state table as code, shared by the row classifier and the SQL census.

    ``ready_stale`` requires the merge's stamp under a mergeable token, not just coexisting keys.
    """
    if isinstance(token, str) and token:
        if has_topics_key and topics_present and has_stale_since and token in STALENESS_MERGE_TOKENS:
            return READY_STALE
        return token
    if not has_topics_key:
        return UNCLASSIFIED
    return READY_FRESH_WITH_TOPICS if topics_present else READY_FRESH_PROVEN_EMPTY


def classify_plan_state(config: Mapping[str, Any] | None) -> str:
    """The plan state of one config; unknown not-determined tokens are returned verbatim."""
    cfg = config if isinstance(config, Mapping) else {}
    topics = cfg.get(TRACKED_TOPICS_KEY)
    has_topics_key = isinstance(topics, list)
    return _state_from_parts(
        cfg.get(NOT_DETERMINED_KEY),
        has_topics_key,
        bool(has_topics_key and topics),
        bool(cfg.get(TRACKED_TOPICS_STALE_SINCE_KEY)),
    )


def plan_coverage_counts(session: Session) -> dict[str, Any]:
    """Census of active monitored contracts by tracking-plan state.

    Partition members sum to ``contracts``. Two overlays ride alongside: ``analysis_failed`` (a failed materialization
    behind some ``no_current_materialization``) and protocol-scoped ``enrollment_deferred_protocols`` (rows that don't
    exist yet).
    """
    # The column is generic JSON with a JSONB variant; cast to reach JSONB operators.
    config = cast(MonitoredContract.monitoring_config, JSONB)
    topics = config[TRACKED_TOPICS_KEY]
    # Coalesce the NULL typeof of a missing key; JSONB equality because ``jsonb_array_length`` errors on non-arrays.
    topics_type = func.coalesce(func.jsonb_typeof(topics), literal("missing"))
    topics_empty = topics == cast(literal("[]"), JSONB)
    token_col = config[NOT_DETERMINED_KEY].astext
    has_stale_since = config[TRACKED_TOPICS_STALE_SINCE_KEY].astext.isnot(None)

    counts: dict[str, int] = {}
    total = 0
    for token, tt, is_empty, stale_since, count in session.execute(
        select(token_col, topics_type, topics_empty, has_stale_since, func.count())
        .where(MonitoredContract.is_active.is_(True))
        .group_by(token_col, topics_type, topics_empty, has_stale_since)
    ).all():
        has_topics_key = tt == "array"
        state = _state_from_parts(token, has_topics_key, has_topics_key and not is_empty, bool(stale_since))
        counts[state] = counts.get(state, 0) + count
        total += count

    not_determined = {state: n for state, n in counts.items() if state not in _PARTITION_NON_TOKEN_STATES}
    return {
        "contracts": total,
        READY_FRESH_WITH_TOPICS: counts.get(READY_FRESH_WITH_TOPICS, 0),
        READY_FRESH_PROVEN_EMPTY: counts.get(READY_FRESH_PROVEN_EMPTY, 0),
        READY_STALE: counts.get(READY_STALE, 0),
        "not_determined": not_determined,
        "not_determined_total": sum(not_determined.values()),
        UNCLASSIFIED: counts.get(UNCLASSIFIED, 0),
        "analysis_failed": _failed_analysis_count(session),
        "enrollment_deferred_protocols": _deferred_enrollment_count(session),
    }


def _deferred_enrollment_count(session: Session) -> int:
    """Protocols queued because a chain head was not determined mid-enrollment."""
    return (
        session.execute(
            select(func.count())
            .select_from(MonitoringEnrollmentQueue)
            .where(MonitoringEnrollmentQueue.reason == HEAD_NOT_DETERMINED_REASON)
        ).scalar()
        or 0
    )


_PARTITION_NON_TOKEN_STATES = frozenset({READY_FRESH_WITH_TOPICS, READY_FRESH_PROVEN_EMPTY, READY_STALE, UNCLASSIFIED})


def _failed_analysis_count(session: Session) -> int:
    """Active monitored contracts whose address has a failed materialization.

    Two queries, not a join: the tables spell chains differently.
    """
    failed = {
        (row.chain, row.address)
        for row in session.execute(
            select(ContractMaterialization.chain, ContractMaterialization.address).where(
                ContractMaterialization.status == "failed"
            )
        ).all()
    }
    if not failed:
        return 0
    monitored = session.execute(
        select(MonitoredContract.chain, MonitoredContract.address).where(MonitoredContract.is_active.is_(True))
    ).all()
    return sum(1 for chain, address in monitored if (chain_cache_token(chain), (address or "").lower()) in failed)
