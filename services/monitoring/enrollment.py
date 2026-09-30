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


# Reasons ``mark_enrollment_dirty`` callers pass; documentation, not enforced.
ENROLLMENT_DIRTY_REASONS = frozenset(
    {
        "policy_complete",
        "analysis_complete",
        "discovery_adoption",
        "audit_added",
        "manual",
        "membership_change",
        "sweep",
        "governance_rotation",
        HEAD_NOT_DETERMINED_REASON,
    }
)


# Retrying a chain that just failed re-runs the whole build, so the cadence is stated rather than every tick.
DEFAULT_HEAD_RETRY_DELAY_S = 300


def _head_retry_delay_s() -> int:
    try:
        return max(0, int(os.getenv("PSAT_ENROLLMENT_HEAD_RETRY_DELAY_S", str(DEFAULT_HEAD_RETRY_DELAY_S))))
    except ValueError:
        return DEFAULT_HEAD_RETRY_DELAY_S


def mark_enrollment_dirty(session: Session, protocol_id: int, reason: str, *, delay_s: int = 0) -> None:
    """Upsert *protocol_id* into the enrollment queue (new row, or bump ``dirty_at`` and ``reason``).

    Re-marking a protocol mid-build re-arms it: the drain's guarded delete keeps the row. ``delay_s`` postpones a retry
    of a condition that can't have changed yet (an unreachable chain). Doesn't commit; callers mark after their
    triggering write commits.
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
    """Low-latency enrollment from PolicyWorker right after a job completes; returns whether enrollment ran.

    *exclude_job_id* is the calling job, still ``processing``, whose address is included anyway. No gate on sibling jobs
    still running: a hung sibling used to silence enrollment, and enrollment is idempotent with the reconciler as
    backstop.
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

    # Transaction-scoped advisory lock so two policy workers don't enroll the same protocol in parallel (deadlocks,
    # duplicate builds). Only the fast path is gated; the drain and manual re-enroll never skip.
    got_lock = session.execute(
        text("SELECT pg_try_advisory_xact_lock(hashtext('protocol_enrollment'), :pid)"),
        {"pid": protocol_id},
    ).scalar()
    if not got_lock:
        # A sibling is enrolling from a snapshot that may predate this job, and its dirty row may be drained first.
        # Commit (unlike the usual convention) so the mark lands before returning.
        mark_enrollment_dirty(session, protocol_id, "policy_complete")
        session.commit()
        logger.debug("Protocol %s enrollment already in progress; marked dirty for reconcile", protocol_id)
        return False

    # Skip the expensive controller pass here; the reconciler and manual re-enroll converge it.
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
    """Create or update MonitoredContract rows for a protocol's analyzed contracts; returns them.

    Idempotent and concurrency-safe (ON CONFLICT on (address, chain)). Also creates WatchedProxy rows and, when
    *enroll_controllers*, enrolls controllers via ``build_governance_view`` (the expensive part, skipped by the fast
    path). *calling_job_id* is the still-processing triggering job.
    """
    # Only analyzed contracts, not the whole inventory.
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
    if calling_job_id is not None:
        calling_job = session.get(Job, calling_job_id)
        if calling_job and calling_job.address:
            analyzed_addrs.add(calling_job.address)

    # One global row order across enrollers so concurrent UPDATEs can't form an AB/BA deadlock.
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

    # Upgrade ``unknown`` control_graph_nodes types from FunctionPrincipal for the chat and analysis-detail readers.
    # Idempotent.
    reconciled = reconcile_control_graph_types(session, [c.id for c in contracts])
    if reconciled:
        session.flush()
        logger.info("Reconciled %d control-graph node types for protocol %s", reconciled, protocol_id)

    # Seed ``last_scanned_block`` from each chain's own head, one read per chain.
    block_by_chain: dict[str, int | None] = {}

    def _block_for(contract_chain: str) -> int | None:
        """The chain head, or ``None`` if unanswered.

        Never 0: that would claim the whole chain as backlog and license every historical event as live. The row is
        skipped for a later pass.
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
    deferred = 0
    # Baseline-only contracts, counted per reason instead of logged per contract.
    plan_not_determined_counts: dict[str, int] = {}

    for contract in contracts:
        contract_chain = contract.chain or chain
        # Chains outside the deployment allowlist keep analysis evidence but get no monitoring rows. Per contract, since
        # protocols mix chains.
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

        summary = session.execute(
            select(ContractSummary).where(ContractSummary.contract_id == contract.id)
        ).scalar_one_or_none()

        cv_rows = (
            session.execute(select(ControllerValue).where(ControllerValue.contract_id == contract.id)).scalars().all()
        )

        contract_type = _determine_contract_type(contract, summary, cv_rows)

        # ``tracked_topics`` feeds the watcher's dispatcher; the raw plan feeds ``build_polling_plan``.
        tracked_topics, tracking_plan, plan_not_determined = _load_tracking_plan_artifacts(session, contract)
        if plan_not_determined:
            plan_not_determined_counts[plan_not_determined] = plan_not_determined_counts.get(plan_not_determined, 0) + 1

        polling_plan = build_polling_plan(
            contract_type=contract_type,
            proxy_type=contract.proxy_type,
            tracking_plan=tracking_plan,
            tracked_topics=tracked_topics,
        )

        monitoring_config = _build_monitoring_config(
            summary, cv_rows, contract_type, tracked_topics, polling_plan, plan_not_determined=plan_not_determined
        )

        existing = session.execute(
            select(MonitoredContract).where(
                MonitoredContract.address == contract.address.lower(),
                MonitoredContract.chain == contract_chain,
            )
        ).scalar_one_or_none()

        if existing is not None:
            # Merge first, so an unreadable plan doesn't replace last-known-good topics with nothing; everything below
            # derives from the merged config.
            monitoring_config = merge_stale_tracking_plan(monitoring_config, existing.monitoring_config)
            # Scan gaps survive every config rebuild.
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
            # Observed values win; re-enrollment only fills gaps. Zero-address values are dropped and keys neither
            # seeded nor polled are pruned (the API serves this map verbatim), except the canonical
            # owner/admin/implementation keys.
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
            is_proxy_shell = contract.is_proxy or bool(contract.proxy_type)
            if not is_proxy_shell:
                existing.watched_proxy_id = None
            mc = existing
        else:
            if current_block is None:
                # No witnessed head, so no honest cursor; a later enrollment creates the row.
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
            # A concurrent enroller may have inserted this (address, chain); only that conflict is ignored.
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
            # Re-fetch whichever row won so later code works on a managed object.
            mc = session.execute(
                select(MonitoredContract).where(
                    MonitoredContract.address == contract.address.lower(),
                    MonitoredContract.chain == contract_chain,
                )
            ).scalar_one()

        # Only real proxy shells, not UUPS implementations that are merely upgradeable.
        if contract_type == "proxy" and (contract.is_proxy or contract.proxy_type):
            if _bridge_to_watched_proxy(session, mc, contract, current_block, contract_chain):
                deferred += 1

        enrolled.append(mc)

    # Controllers need ``build_governance_view``, so they converge on the reconciler cadence or via ``POST
    # /api/protocols/{id}/re-enroll``. Stale detection re-includes existing controller rows, so skipping never
    # deactivates them.
    if enroll_controllers:
        # Controllers enroll on each chain of the contracts they govern, gated per chain.
        deferred += _enroll_controller_addresses(session, contracts, protocol_id, _block_for)
        session.flush()

    # Deactivate (not delete, to keep history) this protocol's rows no longer enrolled, keyed per (address, chain) so
    # twins on other chains aren't confused.
    enrolled_keys = {(mc.address, mc.chain) for mc in enrolled}
    # Must mirror ``_CONTROLLER_MONITORED_TYPES``; omitting 'proxy' once made proxy admins ping-pong between enrolled
    # and deactivated.
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
    # Flushed as one UPDATE batch in PK order, so concurrent passes lock in a deterministic order.
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
        # A pass with deferred rows isn't complete. Re-marking in this transaction advances ``dirty_at`` so the drain
        # keeps the row, and the census can count the deferral.
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
            # Rows watching the baseline registry only, by reason.
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
    """The contract_type from analysis, checking ``is_proxy``/``proxy_type`` first (set even for proxy shells Slither
    never analyzed).
    """
    if contract.is_proxy or contract.proxy_type:
        return "proxy"

    if summary:
        # UUPS implementations report ``is_upgradeable`` but aren't proxies.
        if summary.is_upgradeable and (contract.is_proxy or contract.proxy_type):
            return "proxy"
        if summary.has_timelock:
            return "timelock"
        if summary.is_pausable:
            return "pausable"

    return "regular"


_EVENT_BASED_PROXY_TYPES = {"eip1967", "eip1167", "eip1822"}


def _load_tracking_plan_artifacts(
    session: Session,
    contract: Contract,
) -> tuple[list[dict], dict | None, str | None]:
    """Load *contract*'s tracking plan once: ``(tracked_topics, raw tracking_plan, not_determined)``.

    ``tracked_topics`` feeds the watcher; the raw plan feeds the polling-plan builder;
    ``not_determined`` is ``None`` when the plan was read, else a token naming why not.
    Only the first row below is a finding about the contract:

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
        # No row, not ready, or superseded schema version: none is a finding, so none may persist as empty
        # tracked_topics. DEBUG because this is the normal state before materialization (INFO was a quarter of pipeline
        # log volume).
        logger.debug(
            "no current tracking_plan materialization; enrolling from the baseline registry only",
            extra={"address": contract.address, "chain": contract.chain},
        )
        return [], None, NO_CURRENT_MATERIALIZATION

    try:
        # Only the raise means "not a plan"; ``None`` is proven-absent.
        plan = hydrate_tracking_plan(row)
    except StorageContentIncomplete as exc:
        # Absent objects stay absent on retry; an unreachable bucket may answer next time.
        token = PLAN_OBJECT_ABSENT if isinstance(exc, StorageContentAbsent) else PLAN_NOT_READABLE
        # Enrollment continues on the baseline registry.
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
        # The hand-rolled registry still covers the OZ/Safe/Timelock baseline.
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
    """Build the monitoring_config JSONB from detected capabilities.

    The plan state is always a positive token: ``tracked_topics`` (possibly empty, a witnessed finding) when the plan
    was read, or ``tracking_plan_not_determined`` with the reason when not. Never both; a stored config with both is the
    staleness merge. Neither key marks rows this builder didn't produce.
    """
    config: dict[str, Any] = {
        "watch_upgrades": contract_type == "proxy",
        "watch_ownership": True,
        "watch_pause": False,
        "watch_roles": False,
        "watch_safe_signers": contract_type == "safe",
        # An enabled module acts without meeting the threshold.
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
        # Functionally redundant (missing keys default on) but keeps the config self-describing.
        if any(t.get("event_type") == "authority_updated" for t in tracked_topics or []):
            config["watch_authority"] = True

    if polling_plan:
        config["polling_plan"] = polling_plan

    return config


# Canonical owner/admin ids (as in ``company_overview._ACTIVE_OWNER_CONTROLLER_IDS``), seeded whether or not the polling
# plan names them.
_INITIAL_STATE_OWNER_IDS = frozenset({"owner", "_owner", "state_variable:owner", "state_variable:_owner"})
_INITIAL_STATE_ADMIN_IDS = frozenset({"admin", "state_variable:admin"})


# Always kept in last_known_state when a value exists; the API and reanalysis expect them.
_CANONICAL_STATE_KEYS = frozenset({"owner", "admin", "implementation"})


def _polling_plan_fields(polling_plan: list[dict] | None) -> set[str]:
    if not polling_plan:
        return set()
    return {
        entry["field"]
        for entry in polling_plan
        if isinstance(entry, dict) and isinstance(entry.get("field"), str) and entry["field"]
    }


def _is_zero_address(value: str | None) -> bool:
    """True for the zero address in any hex form; it is never a useful baseline."""
    if not value:
        return False
    v = value.strip().lower()
    if v.startswith("0x"):
        v = v[2:]
    return len(v) > 0 and set(v) == {"0"}


def _candidate_controller_ids_for_field(field: str) -> tuple[str, ...]:
    """Controller_id forms for a state-var name, mirroring the watcher's ``_update_controller_value_rows``."""
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
    """Seed ``last_known_state`` from analysis so the first poll has a baseline and the API has something to show.

    Pass 1 seeds ``implementation`` and canonical owner/admin; pass 2 seeds polling-plan custom slots so their first
    poll doesn't fire a spurious change. Neither overwrites.
    """
    state: dict[str, Any] = {}

    if contract.implementation and not _is_zero_address(contract.implementation):
        state["implementation"] = contract.implementation

    # Zero-address values are never seeded.
    cv_by_id: dict[str, str] = {}
    for cv in controller_values:
        cid = (cv.controller_id or "").lower()
        if cid and cv.value and not _is_zero_address(cv.value):
            cv_by_id.setdefault(cid, cv.value)

    for cid, value in cv_by_id.items():
        if cid in _INITIAL_STATE_OWNER_IDS and "owner" not in state:
            state["owner"] = value
        elif cid in _INITIAL_STATE_ADMIN_IDS and "admin" not in state:
            state["admin"] = value

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
    """Create or link a WatchedProxy for backward compatibility, keyed on the same ``(address, chain)``.

    Returns True when creation was deferred because *current_block* is ``None``.
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
        # Race-safe insert, as for MonitoredContract.
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


# Controller contract_types; demotion scans all of them.
_CONTROLLER_MONITORED_TYPES: tuple[MonitoredContractType, ...] = ("safe", "timelock", "proxy")


def _chain_token(chain: str | None) -> str:
    """Coalesced chain token matching ``company_overview._coalesce_chain`` and the frontend's ``coalesceChain``."""
    token = (chain or "").strip().lower()
    return "ethereum" if token in ("", "mainnet") else token


def _enroll_controller_addresses(
    session: Session,
    contracts: Sequence[Contract],
    protocol_id: int,
    block_for: Callable[[str], int | None],
) -> int:
    """Enroll the protocol's controllers and demote rows that no longer are; returns rows deferred for an
    undetermined head.

    The set is :func:`controllers_for_protocol` (primary controllers plus privileged co-controllers), computed like
    ``/company`` so Monitoring and the canvas can't drift. Co-controllers are included because each emits its own
    events; permissionless callers, fund-destination Safes and EOAs are not. Demotion deactivates rather than deletes,
    and never touches protocol-contract rows. Rows are per (address, chain) of the governed contracts; a missing head
    only blocks creating new rows.
    """
    from services.aggregations.company_overview import controllers_for_protocol

    enrolled_contract_keys = {(c.address.lower(), _chain_token(c.chain)) for c in contracts}
    controllers = controllers_for_protocol(session, protocol_id)
    deferred = 0
    head_by_chain: dict[str, int | None] = {}

    # Sorted, so concurrent drains and re-enrolls lock rows in one order.
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
            # Controllers aren't analyzed, so only vendored entries apply.
            polling_plan = build_polling_plan(
                contract_type=monitored_type,
                proxy_type=None,
                tracking_plan=None,
                tracked_topics=None,
            )
            # Never analyzed: ``contract_not_analyzed`` and no tracked_topics.
            config = _build_monitoring_config(
                None, [], monitored_type, None, polling_plan, plan_not_determined=CONTRACT_NOT_ANALYZED
            )
            # Race-safe insert.
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

    # Demote auto-enrolled controllers that are no longer controllers; protocol-contract rows excluded.
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
