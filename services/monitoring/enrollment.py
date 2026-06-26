"""Auto-enrollment of protocol contracts into the unified monitoring system."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy import select
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
    WatchedProxy,
)
from services.governance.control_graph_types import reconcile_control_graph_types
from services.monitoring.event_topics import extract_governance_topics
from services.monitoring.polling_plan import build_polling_plan
from utils.rpc import rpc_request

logger = logging.getLogger(__name__)


def maybe_enroll_protocol(
    session: Session,
    protocol_id: int,
    rpc_url: str,
    chain: str = "ethereum",
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
    chain: str = "ethereum",
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

    contracts = [
        c
        for c in session.execute(select(Contract).where(Contract.protocol_id == protocol_id)).scalars().all()
        if c.address.lower() in {a.lower() for a in analyzed_addrs if a}
    ]

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

    # Get current block number for last_scanned_block
    try:
        result = rpc_request(rpc_url, "eth_blockNumber", [])
        current_block = int(result, 16)
    except Exception:
        logger.warning("Could not get current block, defaulting to 0")
        current_block = 0

    enrolled: list[MonitoredContract] = []

    for contract in contracts:
        contract_chain = contract.chain or chain

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
        tracked_topics, tracking_plan = _load_tracking_plan_artifacts(session, contract)

        polling_plan = build_polling_plan(
            contract_type=contract_type,
            proxy_type=contract.proxy_type,
            tracking_plan=tracking_plan,
            tracked_topics=tracked_topics,
        )

        # Build monitoring config and initial state
        monitoring_config = _build_monitoring_config(summary, cv_rows, contract_type, tracked_topics, polling_plan)
        initial_state = _build_initial_state(contract, cv_rows, polling_plan)
        needs_poll = bool(polling_plan)

        # Check for existing MonitoredContract
        existing = session.execute(
            select(MonitoredContract).where(
                MonitoredContract.address == contract.address.lower(),
                MonitoredContract.chain == contract_chain,
            )
        ).scalar_one_or_none()

        if existing:
            existing.protocol_id = protocol_id
            existing.contract_id = contract.id
            existing.contract_type = contract_type
            existing.monitoring_config = monitoring_config
            existing.last_known_state = initial_state
            existing.needs_polling = needs_poll
            existing.is_active = True
            # Clear stale watched_proxy link when contract isn't an actual proxy shell
            is_proxy_shell = contract.is_proxy or bool(contract.proxy_type)
            if not is_proxy_shell:
                existing.watched_proxy_id = None
            mc = existing
        else:
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
            _bridge_to_watched_proxy(session, mc, contract, current_block)

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
        _enroll_controller_addresses(session, contracts, protocol_id, chain, current_block)
        # Flush so controller rows are visible to the stale-detection query below.
        session.flush()

    # Deactivate stale MonitoredContract rows for this protocol that are no
    # longer in the enrolled set (e.g. inventory addresses that were never
    # analyzed).  We keep them (is_active=False) rather than deleting so
    # historical events are preserved.
    enrolled_addrs = {mc.address for mc in enrolled}
    # Also include controller-discovered addresses so the stale-detection
    # query below doesn't deactivate rows that ``_enroll_controller_addresses``
    # just enrolled or kept active. Must mirror ``_CONTROLLER_MONITORED_TYPES``
    # — leaving 'proxy' out caused a ping-pong where Pass 1 re-promoted a
    # CGN-discovered proxy admin and the stale check then immediately
    # deactivated it because 'proxy' wasn't in this subset.
    enrolled_addrs |= {
        mc.address
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
    stale = (
        session.execute(
            select(MonitoredContract).where(
                MonitoredContract.protocol_id == protocol_id,
                MonitoredContract.enrollment_source == "auto",
                MonitoredContract.address.notin_(enrolled_addrs),
            )
        )
        .scalars()
        .all()
    )
    for mc in stale:
        mc.is_active = False

    if stale:
        logger.info("Deactivated %d stale monitored contracts for protocol %s", len(stale), protocol_id)

    session.commit()
    logger.info(
        "Enrolled %d contracts for protocol %s",
        len(enrolled),
        protocol_id,
    )
    return enrolled


def _determine_contract_type(
    contract: Contract,
    summary: ContractSummary | None,
    controller_values: Sequence[ControllerValue],
) -> str:
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
) -> tuple[list[dict], dict | None]:
    """Hydrate the analysis ``tracking_plan`` for *contract* once and
    return both projections the enrollment path needs:

      * ``tracked_topics`` — per-contract event-topic specs the watcher
        dispatches on. Same shape as ``extract_governance_topics``.
      * the raw ``tracking_plan`` dict — the polling-plan builder walks
        ``tracked_controllers`` directly so it can read each entry's
        ``read_spec`` / ``polling_fallback`` without losing context.

    Returns ``([], None)`` when the materialization row is missing /
    the status isn't ready / a blob fetch fails. The watcher still has
    the hand-rolled topic registry as a baseline for events and the
    vendored proxy/safe/timelock templates as a baseline for polling.
    """
    try:
        row = find_by_address(session, chain=contract.chain or "ethereum", address=contract.address)
        if row is None:
            return [], None
        plan = hydrate_tracking_plan(row)
        topics = extract_governance_topics(plan)
        return topics, plan
    except Exception as exc:
        # A blob-fetch hiccup or schema drift in tracking_plan shouldn't
        # block enrollment — the hand-rolled registry still catches the
        # OZ/Safe/Timelock baseline.
        logger.warning(
            "Failed to load tracking_plan for %s: %s",
            contract.address,
            exc,
            extra={"exc_type": type(exc).__name__},
        )
        return [], None


def _build_monitoring_config(
    summary: ContractSummary | None,
    controller_values: Sequence[ControllerValue],  # noqa: ARG001 — reserved for future use
    contract_type: str,
    tracked_topics: list[dict] | None = None,
    polling_plan: list[dict] | None = None,
) -> dict[str, Any]:
    """Build the monitoring_config JSONB based on detected capabilities."""
    config: dict[str, Any] = {
        "watch_upgrades": contract_type == "proxy",
        "watch_ownership": True,
        "watch_pause": False,
        "watch_roles": False,
        "watch_safe_signers": contract_type == "safe",
        "watch_timelock": contract_type == "timelock",
    }

    if summary:
        if summary.is_pausable:
            config["watch_pause"] = True
        if summary.control_model and "role" in (summary.control_model or "").lower():
            config["watch_roles"] = True

    if tracked_topics:
        config["tracked_topics"] = tracked_topics
        # Default-on the authority flag if any tracked event_type drives it.
        # ``_should_watch`` falls back to True for missing keys, so the
        # explicit set is more documentation than functional — but it keeps
        # the config self-describing on inspection.
        if any(t.get("event_type") == "authority_updated" for t in tracked_topics):
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

    if contract.implementation:
        state["implementation"] = contract.implementation

    cv_by_id: dict[str, str] = {}
    for cv in controller_values:
        cid = (cv.controller_id or "").lower()
        if cid and cv.value:
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
    current_block: int,
) -> None:
    """Create or link a WatchedProxy row for backward compatibility."""
    existing_wp = session.execute(
        select(WatchedProxy).where(
            WatchedProxy.proxy_address == contract.address.lower(),
            WatchedProxy.chain == (contract.chain or "ethereum"),
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
        # Race-safe on uq_watched_proxy_address_chain — same rationale as the
        # MonitoredContract insert: a concurrent enroller for the same proxy
        # shell must become a no-op rather than poison the session.
        session.execute(
            pg_insert(WatchedProxy)
            .values(
                id=uuid.uuid4(),
                proxy_address=contract.address.lower(),
                chain=contract.chain or "ethereum",
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
                WatchedProxy.chain == (contract.chain or "ethereum"),
            )
        ).scalar_one()
        mc.watched_proxy_id = wp.id


# MonitoredContract.contract_type values this module materializes for
# controller principals. Pass 2 in ``_enroll_controller_addresses`` scans the
# full set so a controller of any flavor gets demoted once it stops being a
# controller (primary or co-controller).
_CONTROLLER_MONITORED_TYPES = ("safe", "timelock", "proxy")


def _enroll_controller_addresses(
    session: Session,
    contracts: Sequence[Contract],
    protocol_id: int,
    chain: str,
    current_block: int,
) -> None:
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
    """
    from services.aggregations.company_overview import controllers_for_protocol

    enrolled_contract_addrs = {c.address.lower() for c in contracts}
    controllers = controllers_for_protocol(session, protocol_id)

    # Pass 1: enroll / re-promote each controller (primary + co-controller).
    for addr, monitored_type in controllers.items():
        if not addr or addr in enrolled_contract_addrs:
            continue
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
            config = _build_monitoring_config(None, [], monitored_type, None, polling_plan)
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
        if not addr or addr in enrolled_contract_addrs:
            continue
        if addr in controllers:
            continue
        mc.is_active = False
        mc.enrollment_source = "auto_deprimary"
