"""The tracking-plan state a ``monitoring_config`` carries, in one place.

Three things live here because they are the same vocabulary seen from three
sides:

  * **the tokens** — every reason a tracking plan could not be read. Produced by
    ``services.monitoring.enrollment._load_tracking_plan_artifacts`` (five), by
    its caller for an address no analysis ever ran on (one), and by the PATCH /
    upsert route for a caller-authored config (one).
  * **the staleness merge** — what re-enrollment does when the plan is
    not-determined *and* the row already carries topics a plan read did name.
  * **the coverage census** — how many monitored contracts are watching on a
    read plan, on a dated plan, or on nothing but the baseline registry, and
    for which reason.

The config discriminant is always a POSITIVE token; no state is signalled by
key absence (see ``_build_monitoring_config``). The four states a row can be
in, and how they read here:

===========================  ==============================  ================
``tracked_topics``           ``tracking_plan_not_determined`` state
===========================  ==============================  ================
present                      absent                          ready_fresh
present                      present                         ready_stale
absent                       present                         not_determined
absent                       absent                          unclassified
===========================  ==============================  ================

``ready_stale`` is the state F5 mints: watching continues on the last plan we
actually read, marked with the instant it stopped being confirmable. It is
neither fresh (we cannot re-read it) nor ignorance (we know what it said) —
collapsing it into either is the failure this module exists to prevent.
``unclassified`` is a row this builder never produced (pre-discriminant), which
is a not-determined fact about our own record, not about the contract.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from sqlalchemy import cast, func, literal, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session

from db.models import ContractMaterialization, MonitoredContract
from utils.chains import chain_cache_token

# --- config keys -----------------------------------------------------------

TRACKED_TOPICS_KEY = "tracked_topics"
NOT_DETERMINED_KEY = "tracking_plan_not_determined"
POLLING_PLAN_KEY = "polling_plan"
#: When the carried-forward topics stopped being confirmable — i.e. the first
#: re-enrollment that could not re-read the plan. The topics are last-known-good
#: as of some instant at or before this one.
TRACKED_TOPICS_STALE_SINCE_KEY = "tracked_topics_stale_since"
POLLING_PLAN_STALE_SINCE_KEY = "polling_plan_stale_since"

# --- not-determined tokens -------------------------------------------------

#: ``find_by_address`` raised.
MATERIALIZATION_LOOKUP_FAILED = "materialization_lookup_failed"
#: No row / not ready / superseded schema version — ``find_by_address`` reads
#: all three as a miss.
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

#: The tokens whose config may inherit the last-read plan. Everything that means
#: "we could not read the plan this time" does; ``config_supplied_by_caller``
#: does not — a caller-authored config is a deliberate overwrite, and
#: resurrecting analyzer topics over it would watch topics the operator just
#: replaced.
STALENESS_MERGE_TOKENS = PLAN_NOT_DETERMINED_TOKENS - {CONFIG_SUPPLIED_BY_CALLER}

# --- plan states -----------------------------------------------------------

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

    Enrollment rebuilds ``monitoring_config`` wholesale, so a plan read that
    fails *this* time would otherwise replace a witnessed topic list with a
    not-determined token and nothing to watch — downstream indistinguishable
    from "the plan was read and named nothing". Dated knowledge is still
    knowledge: the topics stay, stamped with the instant they stopped being
    confirmable, alongside the token saying why they cannot be refreshed.

    Returns *new_config* unchanged unless all of:

      * the new config's token is in :data:`STALENESS_MERGE_TOKENS`;
      * the existing config actually carries topics a plan read named
        (an empty list carries nothing forward — proven-empty is a claim about
        the contract that we can no longer make);
      * the existing config's own provenance is an analyzer plan read, fresh or
        already-stale — never a caller-authored config.

    The polling plan rides along under the same rule. It is the poll plane's
    half of the same watching: dropping it would flip ``needs_polling`` off and
    prune the observed ``last_known_state`` keys it names, which is the same
    manufactured ignorance one layer down.
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
        # First failure to re-read: from here the topics are dated. A later
        # failure keeps this instant — re-enrolling does not refresh them.
        stale_since = (now or _utcnow()).isoformat()

    merged = dict(new_config)
    merged[TRACKED_TOPICS_KEY] = list(last_good)
    merged[TRACKED_TOPICS_STALE_SINCE_KEY] = stale_since
    # Re-derived from the carried topics rather than copied: the flag is a
    # function of what is being watched, and the watch list is what moved.
    if any(isinstance(t, Mapping) and t.get("event_type") == "authority_updated" for t in last_good):
        merged["watch_authority"] = True

    merged_plan = _merge_polling_plan(new_config.get(POLLING_PLAN_KEY), existing_config.get(POLLING_PLAN_KEY))
    if merged_plan is not None:
        merged[POLLING_PLAN_KEY] = merged_plan
        if len(merged_plan) > len(new_config.get(POLLING_PLAN_KEY) or []):
            merged[POLLING_PLAN_STALE_SINCE_KEY] = existing_config.get(POLLING_PLAN_STALE_SINCE_KEY) or stale_since

    return merged


def _merge_polling_plan(new_plan: Any, existing_plan: Any) -> list[dict] | None:
    """Freshly-derived entries, plus last-good entries for the fields the fresh
    plan cannot name. Returns ``None`` when there is nothing to carry.

    The fresh entries win their field outright: they were derived from the
    contract type this pass. The carried ones are the analyzer-derived slots
    that only a readable plan can produce.
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


def _state_from_parts(token: Any, has_topics_key: bool, topics_present: bool) -> str:
    """The state table at the top of this module, as code. One implementation
    so the row-wise classifier and the SQL census cannot drift."""
    if isinstance(token, str) and token:
        return READY_STALE if (has_topics_key and topics_present) else token
    if not has_topics_key:
        return UNCLASSIFIED
    return READY_FRESH_WITH_TOPICS if topics_present else READY_FRESH_PROVEN_EMPTY


def classify_plan_state(config: Mapping[str, Any] | None) -> str:
    """The plan state of one ``monitoring_config``.

    Returns a not-determined token verbatim when that is the state, so an
    unrecognized token is reported as itself rather than folded into a known
    one.
    """
    cfg = config if isinstance(config, Mapping) else {}
    topics = cfg.get(TRACKED_TOPICS_KEY)
    has_topics_key = isinstance(topics, list)
    return _state_from_parts(cfg.get(NOT_DETERMINED_KEY), has_topics_key, bool(has_topics_key and topics))


def plan_coverage_counts(session: Session) -> dict[str, Any]:
    """Census of active monitored contracts by tracking-plan state.

    Answers the question a quiet monitoring fleet cannot: which contracts are
    quiet because nothing happened, and which are quiet because nothing is
    being watched for them.

    The four partition members sum to ``contracts``::

        ready_fresh_with_topics + ready_fresh_proven_empty
          + ready_stale + sum(not_determined.values()) + unclassified

    ``analysis_failed`` is an **overlay, not a partition member**: it counts the
    subset of rows whose address has a ``status='failed'`` materialization —
    the reason behind some of the ``no_current_materialization`` count (a failed
    row reads as a miss). It is reported separately because "no analysis was
    ever established" and "the analysis was attempted and failed" are different
    facts with different remedies, and the second is only visible from the
    materialization table.
    """
    # The column is declared ``JSON().with_variant(JSONB(), "postgresql")``, so
    # the generic type is what builds expressions — cast to reach the JSONB
    # operators.
    config = cast(MonitoredContract.monitoring_config, JSONB)
    topics = config[TRACKED_TOPICS_KEY]
    # ``jsonb_typeof`` of a missing key is NULL; coalesce before comparing so a
    # missing key can never fall through into the array branch. The empty test
    # is a JSONB equality rather than ``jsonb_array_length``, which errors on a
    # non-array input.
    topics_type = func.coalesce(func.jsonb_typeof(topics), literal("missing"))
    topics_empty = topics == cast(literal("[]"), JSONB)
    token_col = config[NOT_DETERMINED_KEY].astext

    counts: dict[str, int] = {}
    total = 0
    for token, tt, is_empty, count in session.execute(
        select(token_col, topics_type, topics_empty, func.count())
        .where(MonitoredContract.is_active.is_(True))
        .group_by(token_col, topics_type, topics_empty)
    ).all():
        has_topics_key = tt == "array"
        state = _state_from_parts(token, has_topics_key, has_topics_key and not is_empty)
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
    }


_PARTITION_NON_TOKEN_STATES = frozenset({READY_FRESH_WITH_TOPICS, READY_FRESH_PROVEN_EMPTY, READY_STALE, UNCLASSIFIED})


def _failed_analysis_count(session: Session) -> int:
    """Active monitored contracts whose address has a failed materialization.

    Not a SQL join: ``contract_materializations.chain`` holds chain-id tokens
    ('1') while ``monitored_contracts.chain`` holds names ('ethereum'), so the
    columns are only comparable through ``chain_cache_token``. The failed set is
    small (it is bounded by builds that failed), and when it is empty the second
    query is skipped entirely.
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
