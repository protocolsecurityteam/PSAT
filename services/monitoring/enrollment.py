"""Auto-enrollment of protocol contracts into the unified monitoring system."""

from __future__ import annotations

import logging
import os
import uuid
from collections.abc import Callable, Sequence
from typing import Any

from sqlalchemy import func, select, text, tuple_
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from db.contract_materializations import find_by_address, hydrate_tracking_plan
from db.models import (
    Contract,
    ContractSummary,
    ControllerValue,
    Job,
    JobStatus,
    MonitoredContract,
    MonitoringEnrollmentQueue,
    WatchedProxy,
)
from db.storage import StorageContentAbsent, StorageContentIncomplete
from schemas.control_tracking import MonitoredContractType
from services.clients.rpc import rpc_request
from services.governance.control_graph_types import reconcile_control_graph_types
from services.monitoring.chain_rpc import chain_id_for, rpc_for_chain
from services.monitoring.event_topics import extract_governance_topics
from services.monitoring.polling_plan import build_polling_plan
from services.monitoring.tracking_plan_state import (
    CONTRACT_NOT_ANALYZED,
    HEAD_NOT_DETERMINED_REASON,
    MATERIALIZATION_LOOKUP_FAILED,
    NO_CURRENT_MATERIALIZATION,
    PLAN_LOAD_ERROR,
    PLAN_NOT_READABLE,
    PLAN_OBJECT_ABSENT,
    POLLING_PLAN_KEY,
    merge_stale_tracking_plan,
    preserve_scan_plane_facts,
)
from utils.chains import chain_enabled

logger = logging.getLogger(__name__)


# Reason vocabulary for ``mark_enrollment_dirty`` — the write site that
# enqueued the protocol. Kept as documentation; not enforced.
ENROLLMENT_DIRTY_REASONS = frozenset(
    {
        "policy_complete",
        "discovery_adoption",
        "audit_added",
        "manual",
        "sweep",
        "governance_rotation",
        HEAD_NOT_DETERMINED_REASON,
    }
)


#: How long a head-not-determined deferral waits before the drain retries it.
#: The retry re-runs the protocol's full enrollment build (governance view
#: included), and a chain that just failed to answer will not answer a second
#: later — so the cadence is stated, not left at "every tick for the duration of
#: the outage".
DEFAULT_HEAD_RETRY_DELAY_S = 300


def _head_retry_delay_s() -> int:
    try:
        return max(0, int(os.getenv("PSAT_ENROLLMENT_HEAD_RETRY_DELAY_S", str(DEFAULT_HEAD_RETRY_DELAY_S))))
    except ValueError:
        return DEFAULT_HEAD_RETRY_DELAY_S


def mark_enrollment_dirty(session: Session, protocol_id: int, reason: str, *, delay_s: int = 0) -> None:
    """Enqueue *protocol_id* for the enrollment reconciler drain.

    One upsert: a fresh dirty row, or a bump of the existing row's
    ``dirty_at`` with the new ``reason``. The drainer
    (``services.monitoring.reconciler.drain_enrollment_queue``) claims due
    rows, so re-marking a protocol that is mid-build simply re-arms it —
    the drain's ``dirty_at``-guarded delete keeps the re-dirtied row alive.

    ``delay_s`` pushes ``dirty_at`` into the future so the row is not due until
    then. Used by a re-mark that is retrying a condition which cannot have
    changed in the meantime (an unreachable chain): re-arming at now() would
    re-run the whole governance build every drain tick for as long as the
    outage lasts. 0 (the default) keeps the immediate re-arm every other caller
    wants.

    Does not commit; the caller commits so the mark lands atomically with
    (or right after) the action that triggered it. Callers mark *after* the
    triggering write commits, so a dirty row never references rolled-back work.
    """
    dirty_at = func.now() if delay_s <= 0 else text(f"NOW() + INTERVAL '{int(delay_s)} seconds'")
    session.execute(
        pg_insert(MonitoringEnrollmentQueue)
        .values(protocol_id=protocol_id, reason=reason, dirty_at=dirty_at)
        .on_conflict_do_update(
            index_elements=["protocol_id"],
            set_={"dirty_at": dirty_at, "reason": reason},
        )
    )


def maybe_enroll_protocol(
    session: Session,
    protocol_id: int,
    rpc_url: str,
    chain: str,
    exclude_job_id: Any = None,
) -> bool:
    """Low-latency enrollment hint — fires from PolicyWorker.process()
    immediately after a job completes so monitored_contracts catches up
    in the common case without waiting for the reconciler tick.

    Returns True if enrollment ran, False if there's nothing to enroll
    (no completed jobs yet for the protocol).

    *exclude_job_id* identifies the calling PolicyWorker's job (still
    ``processing`` because this is invoked from inside ``process()``)
    so ``enroll_protocol_contracts`` can include its address in the
    analyzed-addrs set despite the not-yet-flipped status.

    Historical note: this used to gate on
    ``Job.status IN (queued, processing)`` to avoid running mid-batch.
    The gate produced silent skips when a sibling job hung in those
    statuses without ever transitioning (terminal discovery failures
    were the observed culprit), and there was no fallback trigger.
    ``enroll_protocol_contracts`` is idempotent — partial enrollment
    is fine and gets upserted by the next caller — so the gate was a
    fragile premature optimization. The reconciler in
    ``services/monitoring/reconciler.py`` is the convergence backstop
    for anything this fast-path misses.
    """
    completed = (
        session.execute(
            select(Job).where(
                Job.protocol_id == protocol_id,
                Job.status == JobStatus.completed,
            )
        )
        .scalars()
        .first()
    )

    if not completed:
        logger.debug("Protocol %s has no completed jobs, skipping enrollment", protocol_id)
        return False

    # Serialize concurrent fast-path enrollers of the SAME protocol. Two policy
    # workers finishing sibling jobs both reach here and would enroll in
    # parallel, deadlocking on monitored_contracts row locks and duplicating the
    # whole build. The lock is transaction-scoped: it releases automatically when
    # this transaction ends, and enroll_protocol_contracts is one transaction
    # with a single commit, so it spans the entire enroll. Different protocols
    # hash to different keys and never contend. Only the fast path is gated — the
    # reconciler drain and manual re-enroll must never skip.
    got_lock = session.execute(
        text("SELECT pg_try_advisory_xact_lock(hashtext('protocol_enrollment'), :pid)"),
        {"pid": protocol_id},
    ).scalar()
    if not got_lock:
        # A sibling holds the lock and is enrolling now. Mark dirty so the
        # reconciler enrolls whatever the holder's contract snapshot missed
        # (its snapshot can predate this job) within one drain tick — this is
        # load-bearing, not belt-and-braces: the holder's dirty row may be
        # drained and deleted before it sees this job's contract. This commit
        # deviates from mark_enrollment_dirty's caller-commits convention so the
        # dirty row lands before the skip returns.
        mark_enrollment_dirty(session, protocol_id, "policy_complete")
        session.commit()
        logger.debug("Protocol %s enrollment already in progress; marked dirty for reconcile", protocol_id)
        return False

    # Fast-path hint: enroll contract rows immediately but skip the
    # primary-controller pass (it runs build_governance_view per call). The
    # reconciler converges controllers on its cadence; manual re-enroll runs
    # them on demand.
    enroll_protocol_contracts(session, protocol_id, rpc_url, chain, exclude_job_id, enroll_controllers=False)
    return True


def enroll_protocol_contracts(
    session: Session,
    protocol_id: int,
    rpc_url: str,
    chain: str,
    calling_job_id: Any = None,
    enroll_controllers: bool = True,
) -> list[MonitoredContract]:
    """Create MonitoredContract rows for all contracts in a protocol.

    Idempotent and concurrency-safe: new rows insert with ON CONFLICT
    (address, chain) DO NOTHING and any pre-existing row is updated in
    place. Also creates WatchedProxy rows for proxy contracts and
    enrolls the protocol's controllers — primary + privileged co-controllers
    (safes, timelocks, proxy admins).

    *calling_job_id* is the job that triggered enrollment — it's still in
    ``processing`` status, so we include it alongside completed jobs.

    *enroll_controllers* gates the primary-controller pass, which runs the
    Surface governance computation (``build_governance_view``) and is the
    expensive part. The per-job fast-path hint (``maybe_enroll_protocol``)
    passes ``False`` so it stays cheap; the reconciler and the manual
    re-enroll route leave it ``True``, so controllers converge on the
    reconcile cadence (or immediately on demand). Contract rows and the CGN
    type reconciliation run regardless.

    Returns list of created/updated MonitoredContract rows.
    """
    # Only enroll contracts that have a completed job — not the entire
    # inventory which may include hundreds of unanalyzed addresses.
    analyzed_addrs = set(
        addr
        for (addr,) in session.execute(
            select(Job.address).where(
                Job.protocol_id == protocol_id,
                Job.status == JobStatus.completed,
                Job.address.isnot(None),
            )
        ).all()
    )
    # The calling job is still processing — include its address too.
    if calling_job_id is not None:
        calling_job = session.get(Job, calling_job_id)
        if calling_job and calling_job.address:
            analyzed_addrs.add(calling_job.address)

    # Sort by lowercased address so every enroller touches monitored_contracts
    # rows in one global order. Two policy workers auto-enrolling the same
    # protocol both run this function; without a shared acquisition order their
    # per-row UPDATEs form an AB/BA cycle and deadlock. Sorted, the second
    # enroller queues on the first conflicting row instead.
    contracts = sorted(
        (
            c
            for c in session.execute(select(Contract).where(Contract.protocol_id == protocol_id)).scalars().all()
            if c.address.lower() in {a.lower() for a in analyzed_addrs if a}
        ),
        key=lambda c: c.address.lower(),
    )

    if not contracts:
        logger.info("Protocol %s has no analyzed contracts, nothing to enroll", protocol_id)
        return []

    # Fold authoritative FunctionPrincipal typing back into control_graph_nodes.
    # The resolution stage leaves a governance Safe/Timelock reachable only
    # through per-function authority typed ``unknown`` (its graph walk never
    # classified it). Enrollment itself no longer reads CGN types — it enrolls
    # the primary controllers computed by ``build_governance_view`` — but the
    # other CGN consumers (the chat context layer, the analysis-detail graph)
    # still read these rows, so reconciling keeps the persisted graph
    # consistent with FP. Idempotent; only upgrades unknown → concrete.
    reconciled = reconcile_control_graph_types(session, [c.id for c in contracts])
    if reconciled:
        session.flush()
        logger.info("Reconciled %d control-graph node types for protocol %s", reconciled, protocol_id)

    # Seed ``last_scanned_block`` from each contract's OWN chain head, not a
    # single mainnet read for every chain. ``rpc_url`` is the mainnet seed /
    # local-fork override; ``rpc_for_chain`` keeps it verbatim for mainnet and
    # resolves the chain's eRPC route otherwise. Memoized per chain so a
    # many-contract protocol issues one head read per chain.
    block_by_chain: dict[str, int | None] = {}

    def _block_for(contract_chain: str) -> int | None:
        """The chain's head, or ``None`` when the read did not answer.

        A head read that failed is not-determined, and block 0 is not its
        stand-in: enrolling at 0 mints a row whose scan cursor claims the whole
        chain as backlog (the scanner then serves it first, every pass, forever)
        and whose enrollment floor licenses every historical event it finds as a
        live change. The caller skips creating the row instead — enrollment is
        idempotent and the reconciler re-runs it.
        """
        if contract_chain not in block_by_chain:
            try:
                result = rpc_request(
                    rpc_for_chain(contract_chain, rpc_url),
                    "eth_blockNumber",
                    [],
                    chain_id=chain_id_for(contract_chain),
                )
                block_by_chain[contract_chain] = int(result, 16)
            except Exception as exc:
                logger.warning(
                    "Chain head not determined; deferring enrollment of new rows on this chain",
                    extra={
                        "chain": contract_chain,
                        "protocol_id": protocol_id,
                        "reason": "head_read_not_determined",
                        "site": "enrollment",
                        "exc_type": type(exc).__name__,
                    },
                )
                block_by_chain[contract_chain] = None
        return block_by_chain[contract_chain]

    enrolled: list[MonitoredContract] = []
    # Rows this pass could not create because a chain head was not determined.
    deferred = 0
    # Contracts enrolled on the baseline registry alone, by the token naming why
    # their analysis plan could not be read. Counted rather than logged per
    # contract — the outcome is the same line every time and the population is
    # every contract of every protocol on every pass.
    plan_not_determined_counts: dict[str, int] = {}

    for contract in contracts:
        contract_chain = contract.chain or chain
        # Gate on the deployment allowlist: a protocol's analyzed
        # contracts can span chains this deployment has not enabled. Retain the
        # analysis/Contract evidence but create no monitoring state — no
        # MonitoredContract or WatchedProxy row for an off-allowlist chain.
        # A single protocol legitimately mixes enabled and non-enabled chains,
        # so this is per-contract, not per-call. Mainnet-only: contract_chain
        # resolves to "ethereum"/None → mainnet → enabled, unchanged.
        if not chain_enabled(contract_chain):
            logger.info(
                "Skipping enrollment: chain not enabled for this deployment",
                extra={
                    "address": contract.address,
                    "chain": contract_chain,
                    "protocol_id": protocol_id,
                    "reason": "chain_not_enabled",
                    "site": "enrollment",
                },
            )
            continue
        current_block = _block_for(contract_chain)

        # Load summary
        summary = session.execute(
            select(ContractSummary).where(ContractSummary.contract_id == contract.id)
        ).scalar_one_or_none()

        # Load controller values
        cv_rows = (
            session.execute(select(ControllerValue).where(ControllerValue.contract_id == contract.id)).scalars().all()
        )

        # Determine contract type
        contract_type = _determine_contract_type(contract, summary, cv_rows)

        # Discover per-contract governance event topics + raw tracking
        # plan from the static analysis. Used twice: ``tracked_topics``
        # feeds the watcher's event dispatcher, and the raw plan feeds
        # ``build_polling_plan`` which projects pollable getters /
        # storage slots from the analyzer's tracked_controllers.
        tracked_topics, tracking_plan, plan_not_determined = _load_tracking_plan_artifacts(session, contract)
        if plan_not_determined:
            plan_not_determined_counts[plan_not_determined] = plan_not_determined_counts.get(plan_not_determined, 0) + 1

        polling_plan = build_polling_plan(
            contract_type=contract_type,
            proxy_type=contract.proxy_type,
            tracking_plan=tracking_plan,
            tracked_topics=tracked_topics,
        )

        # Build monitoring config and initial state
        monitoring_config = _build_monitoring_config(
            summary, cv_rows, contract_type, tracked_topics, polling_plan, plan_not_determined=plan_not_determined
        )

        # Check for existing MonitoredContract
        existing = session.execute(
            select(MonitoredContract).where(
                MonitoredContract.address == contract.address.lower(),
                MonitoredContract.chain == contract_chain,
            )
        ).scalar_one_or_none()

        if existing is not None:
            # Enrollment rebuilds the config wholesale, so a plan we cannot read
            # today would replace what a plan we DID read told us with a token
            # and an empty watch list. Merge first — everything below derives
            # from the config, so the merged plan is what seeds the state and
            # decides whether this row still polls.
            monitoring_config = merge_stale_tracking_plan(monitoring_config, existing.monitoring_config)
            # Independent of the plan state: what this row's scanner never
            # covered stays recorded across every rebuild of the config.
            monitoring_config = preserve_scan_plane_facts(monitoring_config, existing.monitoring_config)
            carried_plan = monitoring_config.get(POLLING_PLAN_KEY)
            if isinstance(carried_plan, list):
                polling_plan = carried_plan

        initial_state = _build_initial_state(contract, cv_rows, polling_plan)
        needs_poll = bool(polling_plan)

        if existing:
            existing.protocol_id = protocol_id
            existing.contract_id = contract.id
            existing.contract_type = contract_type
            existing.monitoring_config = monitoring_config
            # Merge, not replace: an observed value is the live truth and wins,
            # so re-enrollment only fills keys the observation is missing. Two
            # hygiene rules keep the merge from carrying junk forever, since the
            # API serves last_known_state verbatim: a zero-address observation
            # is dropped (the zero address is never a useful baseline; a real
            # renounce re-observes silently), and a key that is neither seeded
            # nor read by the current polling plan is pruned —
            # except the canonical owner/admin/implementation keys, which the
            # API and reanalysis expect whenever a value exists. The insert
            # branch below still seeds wholesale (no observations exist yet).
            allowed_keys = set(initial_state) | _polling_plan_fields(polling_plan) | _CANONICAL_STATE_KEYS
            merged_state = dict(initial_state)
            for key, value in (existing.last_known_state or {}).items():
                if key not in allowed_keys:
                    continue
                if isinstance(value, str) and _is_zero_address(value):
                    continue
                merged_state[key] = value
            existing.last_known_state = merged_state
            existing.needs_polling = needs_poll
            existing.is_active = True
            # Clear stale watched_proxy link when contract isn't an actual proxy shell
            is_proxy_shell = contract.is_proxy or bool(contract.proxy_type)
            if not is_proxy_shell:
                existing.watched_proxy_id = None
            mc = existing
        else:
            if current_block is None:
                # No witnessed head ⇒ no honest cursor and no honest enrollment
                # floor. Skip; the next enrollment (fast path or reconciler)
                # creates the row once the chain answers.
                logger.warning(
                    "Skipping enrollment: chain head not determined",
                    extra={
                        "address": contract.address,
                        "chain": contract_chain,
                        "protocol_id": protocol_id,
                        "reason": "head_read_not_determined",
                        "site": "enrollment",
                    },
                )
                deferred += 1
                continue
            # Concurrent policy workers enrolling the same protocol can insert
            # this (address, chain) between the SELECT above and here. ON
            # CONFLICT DO NOTHING keeps a concurrent loser a no-op instead of a
            # uq_monitored_contract_address_chain violation that would poison
            # the session; only the unique conflict is ignored — any other
            # IntegrityError still raises.
            session.execute(
                pg_insert(MonitoredContract)
                .values(
                    id=uuid.uuid4(),
                    address=contract.address.lower(),
                    chain=contract_chain,
                    protocol_id=protocol_id,
                    contract_id=contract.id,
                    contract_type=contract_type,
                    monitoring_config=monitoring_config,
                    last_known_state=initial_state,
                    last_scanned_block=current_block,
                    enrollment_block=current_block,
                    needs_polling=needs_poll,
                    is_active=True,
                    enrollment_source="auto",
                )
                .on_conflict_do_nothing(index_elements=["address", "chain"])
            )
            # Re-fetch the persistent row — ours if we won the insert, the
            # concurrent winner's otherwise — so the proxy bridge and the
            # enrolled list below operate on a managed ORM object either way.
            mc = session.execute(
                select(MonitoredContract).where(
                    MonitoredContract.address == contract.address.lower(),
                    MonitoredContract.chain == contract_chain,
                )
            ).scalar_one()

        # Create WatchedProxy only for actual proxy shells (is_proxy / proxy_type),
        # not UUPS implementations that are merely "upgradeable" per summary.
        if contract_type == "proxy" and (contract.is_proxy or contract.proxy_type):
            if _bridge_to_watched_proxy(session, mc, contract, current_block, contract_chain):
                deferred += 1

        enrolled.append(mc)

    # Enroll the protocol's controllers (primary + privileged co-controllers).
    # This runs build_governance_view (the Surface computation), so it's gated
    # off the per-job fast-path hint and runs on the reconciler cadence + manual
    # re-enroll instead — the low-latency-hint / cadence-convergence split the
    # reconciler module documents. Controllers therefore land in the Monitoring
    # tab within one reconcile interval of analysis, or immediately via
    # ``POST /api/protocols/{id}/re-enroll``. The stale-detection below
    # re-includes existing controller rows from the DB, so skipping this pass
    # never deactivates controllers a prior reconciler enrolled.
    if enroll_controllers:
        # Chain-as-island: each controller enrolls on the chain(s) of the
        # contracts it governs — ``controllers_for_protocol`` keys per
        # (address, chain) from the per-chain primary contests, so a
        # multichain protocol's Base guardian lands on ``base`` and a Safe
        # shared across chains gets a row per chain it governs on. The
        # ``chain_enabled`` allowlist gate applies per chain inside.
        deferred += _enroll_controller_addresses(session, contracts, protocol_id, _block_for)
        # Flush so controller rows are visible to the stale-detection query below.
        session.flush()

    # Deactivate stale MonitoredContract rows for this protocol that are no
    # longer in the enrolled set (e.g. inventory addresses that were never
    # analyzed).  We keep them (is_active=False) rather than deleting so
    # historical events are preserved.
    # Membership is per (address, chain): the same address is a distinct
    # deployment on each chain, so a stale base twin must not be
    # shadowed by its enrolled ethereum twin — nor a live base row deactivated
    # because only its eth twin is enrolled.
    enrolled_keys = {(mc.address, mc.chain) for mc in enrolled}
    # Also include controller-discovered (address, chain) so the stale-detection
    # query below doesn't deactivate rows that ``_enroll_controller_addresses``
    # just enrolled or kept active. Must mirror ``_CONTROLLER_MONITORED_TYPES``
    # — leaving 'proxy' out caused a ping-pong where Pass 1 re-promoted a
    # CGN-discovered proxy admin and the stale check then immediately
    # deactivated it because 'proxy' wasn't in this subset.
    enrolled_keys |= {
        (mc.address, mc.chain)
        for mc in session.execute(
            select(MonitoredContract).where(
                MonitoredContract.protocol_id == protocol_id,
                MonitoredContract.enrollment_source == "auto",
                MonitoredContract.contract_type.in_(_CONTROLLER_MONITORED_TYPES),
            )
        )
        .scalars()
        .all()
    }
    # These is_active=False mutations have no intervening execute, so they flush
    # as one UPDATE batch at commit. SQLAlchemy orders a same-table batch by
    # primary key, so two concurrent stale passes acquire these row locks in one
    # deterministic (PK) order regardless of query order — no sort needed here.
    # Cross-phase overlap with the address-ordered contract loop above is rare;
    # the caller's broad exception handling plus the dirty-queue drain retry
    # cover it.
    stale = (
        session.execute(
            select(MonitoredContract).where(
                MonitoredContract.protocol_id == protocol_id,
                MonitoredContract.enrollment_source == "auto",
                tuple_(MonitoredContract.address, MonitoredContract.chain).notin_(list(enrolled_keys)),
            )
        )
        .scalars()
        .all()
    )
    for mc in stale:
        mc.is_active = False

    if stale:
        logger.info("Deactivated %d stale monitored contracts for protocol %s", len(stale), protocol_id)

    if deferred:
        # A pass that could not create every row it should have is NOT a
        # completed reconcile, and returning normally would let the drain delete
        # the queue row and stamp last_enrollment_reconcile_at — sending the
        # protocol to the back of the sweep queue with the deferral surviving
        # only as a log line. Re-marking dirty in this same transaction advances
        # ``dirty_at``, which makes the drain's dirty_at-guarded delete a no-op:
        # the row keeps its place and the next tick re-runs the build. It is
        # also what the coverage census counts — a deferred contract has no row
        # to be counted as.
        mark_enrollment_dirty(session, protocol_id, HEAD_NOT_DETERMINED_REASON, delay_s=_head_retry_delay_s())
        logger.warning(
            "Enrollment incomplete: %d row(s) deferred for protocol %s; re-queued",
            deferred,
            protocol_id,
            extra={
                "protocol_id": protocol_id,
                "deferred_rows": deferred,
                "reason": HEAD_NOT_DETERMINED_REASON,
                "site": "enrollment",
            },
        )

    session.commit()
    logger.info(
        "Enrolled %d contracts for protocol %s",
        len(enrolled),
        protocol_id,
        extra={
            "protocol_id": protocol_id,
            "enrolled": len(enrolled),
            "deactivated": len(stale),
            "deferred_rows": deferred,
            # The per-cycle collapse of the old per-contract line: how many rows
            # are watching the baseline registry only, and on what grounds.
            "baseline_only": sum(plan_not_determined_counts.values()),
            "plan_not_determined": plan_not_determined_counts,
        },
    )
    return enrolled


def _determine_contract_type(
    contract: Contract,
    summary: ContractSummary | None,
    controller_values: Sequence[ControllerValue],
) -> MonitoredContractType:
    """Determine the contract_type based on analysis results.

    Checks Contract.is_proxy / proxy_type first — these are populated by the
    static worker even when no ContractSummary exists (e.g. proxy shells that
    are not analyzed by Slither).
    """
    # Contract-level proxy detection (most reliable for EIP-1967 etc.)
    if contract.is_proxy or contract.proxy_type:
        return "proxy"

    if summary:
        # Only trust is_upgradeable when the contract is actually a proxy shell.
        # UUPS implementations report is_upgradeable=True because they contain
        # _authorizeUpgrade, but they are not proxies themselves.
        if summary.is_upgradeable and (contract.is_proxy or contract.proxy_type):
            return "proxy"
        if summary.has_timelock:
            return "timelock"
        if summary.is_pausable:
            return "pausable"

    return "regular"


# Standard proxy types that emit events the scanner already handles.
_EVENT_BASED_PROXY_TYPES = {"eip1967", "eip1167", "eip1822"}


def _load_tracking_plan_artifacts(
    session: Session,
    contract: Contract,
) -> tuple[list[dict], dict | None, str | None]:
    """Hydrate the analysis ``tracking_plan`` for *contract* once and
    return the three things the enrollment path needs:

      * ``tracked_topics`` — per-contract event-topic specs the watcher
        dispatches on. Same shape as ``extract_governance_topics``.
      * the raw ``tracking_plan`` dict — the polling-plan builder walks
        ``tracked_controllers`` directly so it can read each entry's
        ``read_spec`` / ``polling_fallback`` without losing context.
      * ``not_determined`` — ``None`` when we read the plan and can therefore
        speak about it; otherwise a short token naming why we cannot.

    Enrollment degrades to the hand-rolled topic registry and the vendored
    proxy/safe/timelock templates in every case, but the reasons are not the
    same fact. "The analysis read fine and derived no extra topics" is a
    statement about the contract; "no analysis has been materialized for this
    address" and "the blob was unreadable" are statements about our own
    pipeline. Only the first may render as an empty ``tracked_topics``.

    The empty return is reachable four ways and exactly one of them is a
    finding about the contract:

    ==============================  ====================  =========================
    situation                       ``not_determined``    what it means
    ==============================  ====================  =========================
    plan read, no governance events ``None``              proven-absent (a finding)
    no current materialization row  ``no_current_...``    never established
    blob unreadable                 ``plan_not_readable`` storage could not answer
    plan present but malformed      ``plan_load_error``   we failed to read it
    ==============================  ====================  =========================
    """
    try:
        row = find_by_address(session, chain=contract.chain or "ethereum", address=contract.address)
    except Exception as exc:
        logger.warning(
            "materialization lookup for %s failed: %s",
            contract.address,
            exc,
            extra={"exc_type": type(exc).__name__},
        )
        return [], None, MATERIALIZATION_LOOKUP_FAILED

    if row is None:
        # ``find_by_address`` collapses three distinct facts into ``None``: no
        # materialization row exists, a row exists but is not status='ready',
        # and a row exists at a superseded ``analysis_schema_version`` (its
        # docstring: "reads as a miss so a bumped analyzer rebuilds rather
        # than serving a stale bundle"). None of the three is "we found out
        # what the plan says", so none of them may be persisted as an empty
        # tracked_topics — that reads as a finding about the contract.
        # Per-contract at DEBUG, counted per cycle by the caller: this is the
        # ordinary state of a contract whose analysis has not been materialized
        # yet, and one INFO per contract per pass was 26% of a pipeline run's
        # log volume while saying the same thing every time.
        logger.debug(
            "no current tracking_plan materialization; enrolling from the baseline registry only",
            extra={"address": contract.address, "chain": contract.chain},
        )
        return [], None, NO_CURRENT_MATERIALIZATION

    try:
        # ``hydrate_tracking_plan`` keeps the same three states: a dict is
        # proven-present, ``None`` is proven-absent (the row stored no plan at
        # all), and ``StorageContentIncomplete`` is the read falling short.
        # Only the raise is a not-a-plan answer here.
        plan = hydrate_tracking_plan(row)
    except StorageContentIncomplete as exc:
        # Two different remedies, so two different tokens: an object the bucket
        # says it does not hold will read the same on every retry; a bucket that
        # could not be asked may answer next time.
        token = PLAN_OBJECT_ABSENT if isinstance(exc, StorageContentAbsent) else PLAN_NOT_READABLE
        # Degraded, not failing: enrollment continues on the baseline registry
        # and this handler returns rather than raising.
        logger.warning(
            "tracking_plan is not determined; enrolling from the baseline registry only",
            extra={
                "address": contract.address,
                "exc_type": type(exc).__name__,
                "error": str(exc),
                "token": token,
            },
        )
        return [], None, token
    except Exception as exc:
        # Schema drift in tracking_plan shouldn't block enrollment — the
        # hand-rolled registry still catches the OZ/Safe/Timelock baseline.
        logger.warning(
            "Failed to load tracking_plan for %s: %s",
            contract.address,
            exc,
            extra={"exc_type": type(exc).__name__},
        )
        return [], None, PLAN_LOAD_ERROR

    return extract_governance_topics(plan), plan, None


def _build_monitoring_config(
    summary: ContractSummary | None,
    controller_values: Sequence[ControllerValue],  # noqa: ARG001 — reserved for future use
    contract_type: MonitoredContractType,
    tracked_topics: list[dict] | None = None,
    polling_plan: list[dict] | None = None,
    *,
    plan_not_determined: str | None = None,
) -> dict[str, Any]:
    """Build the monitoring_config JSONB based on detected capabilities.

    The tracking-plan discriminant is always a POSITIVE token — the builder
    never signals a state by key absence:

      * ``tracked_topics`` (a list, possibly empty) = the plan was read.
        A non-empty list is the witnessed plan; ``[]`` is the witnessed
        "read and named nothing" finding and may be relied on.
      * ``tracking_plan_not_determined`` = the plan was NOT read; the reason
        token from ``_load_tracking_plan_artifacts`` (or the enrollment
        path) says why. ``tracked_topics`` is then absent — we cannot speak
        about the plan.

    NEITHER key therefore identifies only rows this builder did not produce
    (pre-discriminant rows; caller-supplied configs are stamped at the route,
    see ``routers/monitored.py``). Earlier, the read-and-named-nothing state
    was itself signalled by key absence, making it indistinguishable from
    those rows.

    The builder never emits BOTH keys — it has no access to any earlier read.
    A persisted config carrying both is the staleness merge its caller applies
    (``tracking_plan_state.merge_stale_tracking_plan``): topics from the last
    plan we read, plus the reason we cannot re-read them now."""
    config: dict[str, Any] = {
        "watch_upgrades": contract_type == "proxy",
        "watch_ownership": True,
        "watch_pause": False,
        "watch_roles": False,
        "watch_safe_signers": contract_type == "safe",
        # Module/guard changes decide whether the k/n threshold bounds protection
        # at all — an enabled module acts without meeting it.
        "watch_safe_modules": contract_type == "safe",
        "watch_timelock": contract_type == "timelock",
    }

    if summary:
        if summary.is_pausable:
            config["watch_pause"] = True
        if summary.control_model and "role" in (summary.control_model or "").lower():
            config["watch_roles"] = True

    if plan_not_determined:
        config["tracking_plan_not_determined"] = plan_not_determined
    else:
        config["tracked_topics"] = list(tracked_topics or [])
        # Default-on the authority flag if any tracked event_type drives it.
        # ``_should_watch`` falls back to True for missing keys, so the
        # explicit set is more documentation than functional — but it keeps
        # the config self-describing on inspection.
        if any(t.get("event_type") == "authority_updated" for t in tracked_topics or []):
            config["watch_authority"] = True

    if polling_plan:
        config["polling_plan"] = polling_plan

    return config


# Canonical owner/admin controller_id whitelists. Same shape as
# ``services.aggregations.company_overview._ACTIVE_OWNER_CONTROLLER_IDS``
# — both pick the canonical Ownable slot. Kept here so the initial-state
# seed for the two universally-seeded fields (owner, admin) survives
# whether or not the analyzer surfaced them in the polling plan.
_INITIAL_STATE_OWNER_IDS = frozenset({"owner", "_owner", "state_variable:owner", "state_variable:_owner"})
_INITIAL_STATE_ADMIN_IDS = frozenset({"admin", "state_variable:admin"})


# Fields the API and reanalysis snapshot expect in last_known_state whenever a
# value exists, independent of the polling plan — so the merge keeps them even
# when a plan no longer projects them.
_CANONICAL_STATE_KEYS = frozenset({"owner", "admin", "implementation"})


def _polling_plan_fields(polling_plan: list[dict] | None) -> set[str]:
    """The set of ``field`` names the current polling plan reads."""
    if not polling_plan:
        return set()
    return {
        entry["field"]
        for entry in polling_plan
        if isinstance(entry, dict) and isinstance(entry.get("field"), str) and entry["field"]
    }


def _is_zero_address(value: str | None) -> bool:
    """True for the zero address in any hex form (``0x0``, the 40-zero
    canonical form, or an un-prefixed run of zeros).

    Callers use this to keep a zero value out of ``last_known_state``: the zero
    address is never a meaningful comparison baseline, and a renounced value is
    re-observed as ``0x0`` live with its first observation silent.
    """
    if not value:
        return False
    v = value.strip().lower()
    if v.startswith("0x"):
        v = v[2:]
    return len(v) > 0 and set(v) == {"0"}


def _candidate_controller_ids_for_field(field: str) -> tuple[str, ...]:
    """Controller_id forms the analyzer emits for a given state-var
    name. Mirrors ``_update_controller_value_rows`` in the watcher so
    the polling-plan-driven initial-state seed reads from the same key
    set the runtime sync writes to."""
    return (
        field,
        f"_{field}",
        f"state_variable:{field}",
        f"state_variable:_{field}",
        f"external_contract:{field}",
    )


def _build_initial_state(
    contract: Contract,
    controller_values: Sequence[ControllerValue],
    polling_plan: list[dict] | None = None,
) -> dict[str, Any]:
    """Seed ``last_known_state`` from pre-existing analysis data so the
    poller has a comparison baseline on its first tick and the API has
    something to render before the first observation arrives.

    Two stacked sources, in order:

      1. ``contract.implementation`` plus the canonical owner / admin
         CV slots. These are universally surfaced — the API and
         reanalysis snapshot both rely on ``last_known_state.owner`` /
         ``.admin`` being present whenever the resolution stage produced
         a value, independent of whether the analyzer also surfaced a
         polling entry for them.
      2. Per-polling-plan-field CV seeding for custom slots
         (``protocolAdmin``, ``feeRecipient``, …) so the first poll on
         those slots doesn't fire a spurious state_changed event.

    The two passes operate on disjoint key sets: pass 1 covers
    ``implementation`` / ``owner`` / ``admin`` (and never overwrites);
    pass 2 covers fields named by polling-plan entries that aren't
    already in state.
    """
    state: dict[str, Any] = {}

    if contract.implementation and not _is_zero_address(contract.implementation):
        state["implementation"] = contract.implementation

    # A zero-address CV is never a useful comparison baseline (see
    # _is_zero_address): dropping it here keeps owner/admin and every
    # polling-plan field below out of the seed unless a real address exists.
    cv_by_id: dict[str, str] = {}
    for cv in controller_values:
        cid = (cv.controller_id or "").lower()
        if cid and cv.value and not _is_zero_address(cv.value):
            cv_by_id.setdefault(cid, cv.value)

    # Pass 1: canonical owner/admin seeding from CV rows.
    for cid, value in cv_by_id.items():
        if cid in _INITIAL_STATE_OWNER_IDS and "owner" not in state:
            state["owner"] = value
        elif cid in _INITIAL_STATE_ADMIN_IDS and "admin" not in state:
            state["admin"] = value

    # Pass 2: polling-plan-driven custom-slot seeding.
    if polling_plan:
        for entry in polling_plan:
            if not isinstance(entry, dict):
                continue
            field = entry.get("field")
            if not isinstance(field, str) or not field:
                continue
            if field in state:
                continue
            for candidate in _candidate_controller_ids_for_field(field):
                value = cv_by_id.get(candidate.lower())
                if value:
                    state[field] = value
                    break

    return state


def _bridge_to_watched_proxy(
    session: Session,
    mc: MonitoredContract,
    contract: Contract,
    current_block: int | None,
    chain: str,
) -> bool:
    """Create or link a WatchedProxy row for backward compatibility.

    Returns True when the link had to be deferred (see *current_block*).

    *chain* is the MonitoredContract's resolved chain (``contract.chain`` or the
    caller's fallback), so the WatchedProxy is keyed on the same ``(address,
    chain)`` as its MonitoredContract instead of an independent mainnet default.

    *current_block* is ``None`` when the chain head was not determined; only the
    create branch needs it (same floor-0 cursor hazard as the MonitoredContract
    insert), so the link is deferred to the next pass rather than seeded at 0.
    """

    existing_wp = session.execute(
        select(WatchedProxy).where(
            WatchedProxy.proxy_address == contract.address.lower(),
            WatchedProxy.chain == chain,
        )
    ).scalar_one_or_none()

    poll = (contract.proxy_type or "").lower() not in _EVENT_BASED_PROXY_TYPES

    if existing_wp:
        existing_wp.proxy_type = contract.proxy_type
        existing_wp.last_known_implementation = contract.implementation
        existing_wp.needs_polling = poll
        if not existing_wp.label:
            existing_wp.label = contract.contract_name
        mc.watched_proxy_id = existing_wp.id
    else:
        if current_block is None:
            logger.warning(
                "Skipping WatchedProxy creation: chain head not determined",
                extra={
                    "address": contract.address,
                    "chain": chain,
                    "reason": "head_read_not_determined",
                    "site": "enrollment_watched_proxy",
                },
            )
            return True
        # Race-safe on uq_watched_proxy_address_chain — same rationale as the
        # MonitoredContract insert: a concurrent enroller for the same proxy
        # shell must become a no-op rather than poison the session.
        session.execute(
            pg_insert(WatchedProxy)
            .values(
                id=uuid.uuid4(),
                proxy_address=contract.address.lower(),
                chain=chain,
                label=contract.contract_name,
                proxy_type=contract.proxy_type,
                last_known_implementation=contract.implementation,
                last_scanned_block=current_block,
                needs_polling=poll,
            )
            .on_conflict_do_nothing(index_elements=["proxy_address", "chain"])
        )
        wp = session.execute(
            select(WatchedProxy).where(
                WatchedProxy.proxy_address == contract.address.lower(),
                WatchedProxy.chain == chain,
            )
        ).scalar_one()
        mc.watched_proxy_id = wp.id
    return False


# MonitoredContract.contract_type values this module materializes for
# controller principals. Pass 2 in ``_enroll_controller_addresses`` scans the
# full set so a controller of any flavor gets demoted once it stops being a
# controller (primary or co-controller).
_CONTROLLER_MONITORED_TYPES: tuple[MonitoredContractType, ...] = ("safe", "timelock", "proxy")


def _chain_token(chain: str | None) -> str:
    """Coalesced chain token matching ``company_overview._coalesce_chain`` (and
    the frontend's ``coalesceChain``): NULL/empty/``"mainnet"`` fold to
    ``"ethereum"``, everything else lowercases as-is — so keys built here
    compare equal to ``controllers_for_protocol``'s entity-derived chain half.
    """
    token = (chain or "").strip().lower()
    return "ethereum" if token in ("", "mainnet") else token


def _enroll_controller_addresses(
    session: Session,
    contracts: Sequence[Contract],
    protocol_id: int,
    block_for: Callable[[str], int | None],
) -> int:
    """Enroll the protocol's controllers (Safes / Timelocks / proxy admins) as
    MonitoredContract rows, and demote any that are no longer controllers.

    The enrolled set is :func:`controllers_for_protocol` — the protocol's
    **primary controllers union its privileged co-controllers**, computed by the
    same loaders + ``build_governance_view`` the ``/company`` endpoint uses, so
    Monitoring and the Surface canvas share one source of truth (deriving the
    set a second way here is what historically let the two views drift — a
    fund-destination Safe stored in a state variable landing in Monitoring but
    not on the canvas; or a real governance Safe typed ``unknown`` in the
    control graph showing on the canvas but never enrolled).

    Monitoring watches more than the canvas *groups*: the canvas renders one
    primary controller per contract (winner-take-all) plus secondary
    annotations, while enrollment also watches the co-controllers — a contract
    governed by both a guardian Safe (pause / fund-recovery) and a bigger
    governance Safe needs both monitored, since each emits its own events.
    What's still excluded is genuine noise: permissionless callers (whitelisted
    auction bidders sharing ``createBid``) and fund-destination Safes hold
    neither a primary win nor privileged/tightly-gated authority, so
    :func:`assign_co_controllers` drops them. EOAs are dropped upstream
    (nothing event-bearing to monitor); ``proxy_admin`` is enrolled as the
    historical ``'proxy'`` contract_type.

    Demotion is symmetric: an auto-enrolled controller row whose address is no
    longer a controller is deactivated (``is_active=False``,
    ``enrollment_source="auto_deprimary"``) rather than deleted, so its
    MonitoredEvent history survives a later re-promotion or an audit.
    Protocol-contract rows (owned by the main loop in
    ``enroll_protocol_contracts``) are never touched.

    Controllers enroll per (address, chain): the chain comes from the
    contracts the principal governs (``controllers_for_protocol``'s key), so a
    multichain protocol's Base guardian lands on ``base`` and a Safe shared
    across chains gets one row per chain it governs on. Each chain is gated on
    ``chain_enabled`` individually.

    A ``None`` head block for a chain (head read not determined) suppresses
    only the creation of new rows on that chain — re-promotion and demotion of
    rows that already exist need no cursor and still converge. Returns the
    number of controller rows whose creation was deferred that way.
    """
    from services.aggregations.company_overview import controllers_for_protocol

    enrolled_contract_keys = {(c.address.lower(), _chain_token(c.chain)) for c in contracts}
    controllers = controllers_for_protocol(session, protocol_id)
    deferred = 0
    head_by_chain: dict[str, int | None] = {}

    # Pass 1: enroll / re-promote each controller (primary + co-controller).
    # Sorted by (lowercased address, chain): this loop takes progressive row
    # locks via per-iteration SELECTs, so a concurrent drain and manual
    # re-enroll that overlap here acquire them in one global order and can't
    # deadlock.
    for (addr, chain), monitored_type in sorted(controllers.items()):
        if not addr or (addr, chain) in enrolled_contract_keys:
            continue
        if not chain_enabled(chain):
            logger.info(
                "Skipping controller enrollment: chain not enabled for this deployment",
                extra={
                    "address": addr,
                    "chain": chain,
                    "protocol_id": protocol_id,
                    "reason": "chain_not_enabled",
                    "site": "enrollment_controllers",
                },
            )
            continue
        if chain not in head_by_chain:
            head_by_chain[chain] = block_for(chain)
        current_block = head_by_chain[chain]
        existing = session.execute(
            select(MonitoredContract).where(
                MonitoredContract.address == addr,
                MonitoredContract.chain == chain,
            )
        ).scalar_one_or_none()
        if existing:
            existing.protocol_id = protocol_id
            existing.contract_type = monitored_type
            existing.is_active = True
            existing.enrollment_source = "auto"
        else:
            if current_block is None:
                logger.warning(
                    "Skipping controller enrollment: chain head not determined",
                    extra={
                        "address": addr,
                        "chain": chain,
                        "protocol_id": protocol_id,
                        "reason": "head_read_not_determined",
                        "site": "enrollment_controllers",
                    },
                )
                deferred += 1
                continue
            # Primary controllers are principals on *other* contracts, not
            # analyzed themselves, so the polling plan resolves to vendored
            # entries only — Safe gets ``getThreshold``, Timelock gets
            # ``getMinDelay``, proxy_admin gets nothing (needs_polling=False).
            polling_plan = build_polling_plan(
                contract_type=monitored_type,
                proxy_type=None,
                tracking_plan=None,
                tracked_topics=None,
            )
            # No analysis was ever run on this address, so nothing here has
            # read a tracking plan for it: the config carries the
            # contract_not_analyzed token and no tracked_topics key at all.
            config = _build_monitoring_config(
                None, [], monitored_type, None, polling_plan, plan_not_determined=CONTRACT_NOT_ANALYZED
            )
            # Race-safe on uq_monitored_contract_address_chain — a concurrent
            # reconcile / re-enroll for the same controller must become a no-op
            # rather than poison the session.
            session.execute(
                pg_insert(MonitoredContract)
                .values(
                    id=uuid.uuid4(),
                    address=addr,
                    chain=chain,
                    protocol_id=protocol_id,
                    contract_type=monitored_type,
                    monitoring_config=config,
                    last_known_state={},
                    last_scanned_block=current_block,
                    enrollment_block=current_block,
                    needs_polling=bool(polling_plan),
                    is_active=True,
                    enrollment_source="auto",
                )
                .on_conflict_do_nothing(index_elements=["address", "chain"])
            )

    # Pass 2: demote any active auto-enrolled controller row that is no longer
    # a controller (neither primary nor co-controller). Symmetric with Pass 1 —
    # same signal, opposite direction — covering both "lost its authority" and
    # the zombie case where the controller dropped out of the governance view
    # entirely between runs. Protocol-contract rows are excluded so this never
    # touches MC rows owned by the main contract loop in
    # ``enroll_protocol_contracts``.
    existing_controllers = (
        session.execute(
            select(MonitoredContract).where(
                MonitoredContract.protocol_id == protocol_id,
                MonitoredContract.enrollment_source == "auto",
                MonitoredContract.contract_type.in_(_CONTROLLER_MONITORED_TYPES),
                MonitoredContract.is_active.is_(True),
            )
        )
        .scalars()
        .all()
    )
    for mc in existing_controllers:
        addr = (mc.address or "").lower()
        key = (addr, _chain_token(mc.chain))
        if not addr or key in enrolled_contract_keys:
            continue
        if key in controllers:
            continue
        mc.is_active = False
        mc.enrollment_source = "auto_deprimary"

    return deferred
