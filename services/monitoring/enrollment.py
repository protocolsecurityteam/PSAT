"""Auto-enrollment of protocol contracts into the unified monitoring system."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from db.models import (
    Contract,
    ContractSummary,
    ControlGraphNode,
    ControllerValue,
    EffectiveFunction,
    FunctionPrincipal,
    Job,
    JobStatus,
    MonitoredContract,
    WatchedProxy,
)
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

    enroll_protocol_contracts(session, protocol_id, rpc_url, chain, exclude_job_id)
    return True


def enroll_protocol_contracts(
    session: Session,
    protocol_id: int,
    rpc_url: str,
    chain: str = "ethereum",
    calling_job_id: Any = None,
) -> list[MonitoredContract]:
    """Create MonitoredContract rows for all contracts in a protocol.

    Performs upsert (ON CONFLICT address+chain DO UPDATE) so this is
    idempotent. Also creates WatchedProxy rows for proxy contracts and
    discovers controller addresses (safes, timelocks) from the control graph.

    *calling_job_id* is the job that triggered enrollment — it's still in
    ``processing`` status, so we include it alongside completed jobs.

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

        # Build monitoring config and initial state
        monitoring_config = _build_monitoring_config(summary, cv_rows, contract_type)
        initial_state = _build_initial_state(contract, cv_rows)
        needs_poll = _needs_polling(contract_type, contract)

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
            mc = MonitoredContract(
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
            session.add(mc)
            session.flush()

        # Create WatchedProxy only for actual proxy shells (is_proxy / proxy_type),
        # not UUPS implementations that are merely "upgradeable" per summary.
        if contract_type == "proxy" and (contract.is_proxy or contract.proxy_type):
            _bridge_to_watched_proxy(session, mc, contract, current_block)

        enrolled.append(mc)

    # Discover controller addresses from the control graph
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


def _needs_polling(contract_type: str, contract: Contract) -> bool:
    """Decide whether a contract needs the state-polling loop.

    EIP-1967 (and other standard) proxies emit Upgraded / AdminChanged events
    that the event scanner picks up — no polling required.  Only safes,
    timelocks, and non-standard (custom) proxies need polling.
    """
    if contract_type in ("safe", "timelock"):
        return True
    if contract_type == "proxy":
        return (contract.proxy_type or "").lower() not in _EVENT_BASED_PROXY_TYPES
    return False


def _build_monitoring_config(
    summary: ContractSummary | None,
    controller_values: Sequence[ControllerValue],  # noqa: ARG001 — reserved for future use
    contract_type: str,
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

    return config


# The active owner / admin slot, controller-id whitelist. Same shape as
# ``services.aggregations.company_overview._ACTIVE_OWNER_CONTROLLER_IDS``
# — both are picking the canonical Ownable slot. A loose substring match
# (``"owner" in controller_id``) used to drive this and false-positives
# on ``pendingOwner``, ``previousOwner``, ``roleOwner``, ``ownerFee``,
# etc. Combined with last-write-wins iteration the wrong slot would
# latch into ``last_known_state.owner`` and the scanner would
# false-positive an OwnershipTransferred when the live owner finally
# diverged from the stored pending-owner value.
_INITIAL_STATE_OWNER_IDS = frozenset({"owner", "_owner", "state_variable:owner", "state_variable:_owner"})
_INITIAL_STATE_ADMIN_IDS = frozenset({"admin", "state_variable:admin"})


def _build_initial_state(
    contract: Contract,
    controller_values: Sequence[ControllerValue],
) -> dict[str, Any]:
    """Build the last_known_state dict from existing pipeline data."""
    state: dict[str, Any] = {}

    if contract.implementation:
        state["implementation"] = contract.implementation

    for cv in controller_values:
        cid = (cv.controller_id or "").lower()
        if not cv.value:
            continue
        if cid in _INITIAL_STATE_OWNER_IDS:
            state["owner"] = cv.value
        elif cid in _INITIAL_STATE_ADMIN_IDS:
            state["admin"] = cv.value

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
        wp = WatchedProxy(
            id=uuid.uuid4(),
            proxy_address=contract.address.lower(),
            chain=contract.chain or "ethereum",
            label=contract.contract_name,
            proxy_type=contract.proxy_type,
            last_known_implementation=contract.implementation,
            last_scanned_block=current_block,
            needs_polling=poll,
        )
        session.add(wp)
        session.flush()
        mc.watched_proxy_id = wp.id


# CGN ``resolved_type`` → principal type understood by
# :func:`assign_primary_controllers`. EOAs are intentionally absent
# even though they're valid principals — there's nothing useful to
# monitor on an EOA (no contract events, no state), and the prior
# enrollment behavior never materialized MonitoredContract rows for
# them. The company-overview path keeps EOAs in its principal list so
# they still surface as Surface group containers when they win
# primary_for.
_CGN_TYPE_TO_PRINCIPAL_TYPE = {
    "safe": "safe",
    "gnosis_safe": "safe",
    "timelock": "timelock",
    "proxy": "proxy_admin",
    "proxy_admin": "proxy_admin",
}


# MonitoredContract.contract_type values populated by this module via
# ``_CGN_TYPE_TO_PRINCIPAL_TYPE``. Pass 2 below scans the full set so
# zombies of every flavor get caught.
_CONTROLLER_MONITORED_TYPES = ("safe", "timelock", "proxy")


def _enroll_controller_addresses(
    session: Session,
    contracts: Sequence[Contract],
    protocol_id: int,
    chain: str,
    current_block: int,
) -> None:
    """Discover and enroll controller addresses from control graph nodes.

    A CGN principal (Safe / Timelock / proxy admin) is enrolled iff it
    holds function-level authority on at least one protocol contract —
    i.e. an address that appears in ``FunctionPrincipal`` for any
    ``EffectiveFunction`` of one of *contracts*. CGN on its own
    over-enrolls because the table also stores state-variable
    destinations (``accountantState.payoutAddress`` pointing at a Safe
    that's actually a fee sink, not a governor); ``FunctionPrincipal``
    is the authoritative "can actually call something" signal already
    trusted by ``services.aggregations.company_overview``.

    The Surface canvas uses a *single* primary controller per contract
    (winner-take-all by :func:`assign_primary_controllers`) so groups
    don't overlap. Enrollment intentionally uses the broader
    *eligibility* check: a contract owned by both a Safe and a
    Timelock needs both to be monitored (each emits its own events),
    even though Surface only renders the Safe's group.

    Demotion is symmetric with enrollment and is driven by the same FP
    signal — every auto-enrolled controller row whose address has no
    current FP authority on the protocol's contracts is deactivated
    (``is_active=False``, ``enrollment_source="auto_deprimary"``),
    regardless of whether CGN still surfaces it. That covers both the
    "Safe lost its function gate" case (CGN still present) and the
    "Safe fell out of CGN entirely" zombie case observed on prod
    (timelocks enrolled in a prior run whose CGN nodes disappeared
    when analysis was rebuilt — the deployed code had no path to
    remove them). Demoted rows are kept rather than deleted so
    MonitoredEvent history survives a re-promotion or audit.
    """
    enrolled_contract_addrs = {c.address.lower() for c in contracts}

    # Collect every candidate principal from the CGN walk.
    candidates_by_addr: dict[str, str] = {}
    for contract in contracts:
        nodes = (
            session.execute(select(ControlGraphNode).where(ControlGraphNode.contract_id == contract.id)).scalars().all()
        )
        for node in nodes:
            addr = node.address.lower() if node.address else ""
            if not addr or addr in enrolled_contract_addrs:
                continue
            ptype = _CGN_TYPE_TO_PRINCIPAL_TYPE.get(node.resolved_type or "")
            if not ptype:
                continue
            # First-write-wins; CGN-resolved type for an address shouldn't
            # vary across contracts within a single protocol, and if it
            # does the difference is uninteresting for the enrollment
            # decision (we just need to know it's some kind of principal).
            candidates_by_addr.setdefault(addr, ptype)

    # Eligibility: the set of FP-tagged addresses across this protocol's
    # contracts. An address is enrollment-eligible iff it appears here.
    # We compute this even when candidates_by_addr is empty so Pass 2 can
    # still demote zombies whose CGN evidence is gone.
    contract_ids = [c.id for c in contracts]
    fp_eligible_addrs: set[str] = set()
    if contract_ids:
        for (fp_addr,) in session.execute(
            select(func.lower(FunctionPrincipal.address))
            .join(EffectiveFunction, EffectiveFunction.id == FunctionPrincipal.function_id)
            .where(
                EffectiveFunction.contract_id.in_(contract_ids),
                FunctionPrincipal.address.is_not(None),
                or_(
                    FunctionPrincipal.principal_type != "signature_witness",
                    FunctionPrincipal.principal_type.is_(None),
                ),
            )
            .distinct()
        ).all():
            if fp_addr:
                fp_eligible_addrs.add(fp_addr)

    # Pass 1: enroll / re-promote candidates that currently hold FP authority.
    for addr, ptype in candidates_by_addr.items():
        if addr not in fp_eligible_addrs:
            continue
        # proxy_admin maps to MonitoredContract.contract_type='proxy'
        # (schema's historical naming); other principal types pass through.
        monitored_type = "proxy" if ptype == "proxy_admin" else ptype
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
            config = _build_monitoring_config(None, [], monitored_type)
            session.add(
                MonitoredContract(
                    id=uuid.uuid4(),
                    address=addr,
                    chain=chain,
                    protocol_id=protocol_id,
                    contract_type=monitored_type,
                    monitoring_config=config,
                    last_known_state={},
                    last_scanned_block=current_block,
                    needs_polling=monitored_type in ("safe", "timelock"),
                    is_active=True,
                    enrollment_source="auto",
                )
            )

    # Pass 2: demote any active auto-enrolled controller row whose
    # address has no FP authority on this protocol. Symmetric with
    # Pass 1 — same signal, opposite direction. Catches both the
    # "CGN-present, FP-absent" demotion AND the zombie case where the
    # CGN row vanished entirely between enrollment runs. Protocol-
    # contract rows are excluded so this never touches MC rows owned
    # by the main contract loop in ``enroll_protocol_contracts``.
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
        if addr in fp_eligible_addrs:
            continue
        mc.is_active = False
        mc.enrollment_source = "auto_deprimary"
