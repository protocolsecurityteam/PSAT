"""Queue re-analysis jobs when governance events indicate stale analysis data."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models import (
    Contract,
    ContractSummary,
    ControllerValue,
    EffectiveFunction,
    Job,
    JobStatus,
    MonitoredContract,
)
from db.queue import create_job
from services.monitoring.event_topics import _HANDROLLED_EVENT_TYPE_TO_TAGS
from utils.chains import chain_enabled

# Must match _OWNER_CONTROLLER_IDS in unified_watcher.py.
_OWNER_CONTROLLER_IDS = ("owner", "state_variable:owner")

logger = logging.getLogger(__name__)


# Write targets whose mutation invalidates the control graph, permissions or implementation hash.
_REANALYSIS_WRITE_TARGETS = frozenset(
    {
        "owner",
        "_owner",
        "pendingOwner",
        "authority",
        "admin",
        "_admin",
        "pendingAdmin",
        "future_admin",
        "_initialized",
        "_initializing",
    }
)

# Poll fields that always trigger reanalysis. ``implementation`` comes from the vendored EIP-1967 poll entry, which
# never flows through the write targets.
REANALYSIS_POLL_FIELDS_VENDORED = frozenset({"implementation"})


def should_trigger_reanalysis(event_type: str, data: dict | None = None) -> bool:
    """Whether *event_type* (with optional *data*) warrants re-analysis.

    Tag-driven: control-slot writes, delegatecalls or Initializable runs trigger it. Bare event types synthesize tags
    via ``_HANDROLLED_EVENT_TYPE_TO_TAGS``. Poll changes use the same write-target vocabulary.
    """
    if (event_type == "state_changed_poll" or event_type.startswith("value_changed")) and data:
        # Read-observed changes: the changed field is the witnessed fact, so key off it rather than the emitter's write
        # set.
        field = data.get("field")
        if field in REANALYSIS_POLL_FIELDS_VENDORED:
            return True
        if isinstance(field, str) and field in _REANALYSIS_WRITE_TARGETS:
            return True
        return False

    tags: dict | None = None
    if isinstance(data, dict):
        candidate = data.get("effect_tags")
        if isinstance(candidate, dict):
            tags = candidate
    if tags is None:
        tags = _HANDROLLED_EVENT_TYPE_TO_TAGS.get(event_type)

    if not isinstance(tags, dict):
        return False

    writes = tags.get("writes") or []
    if any(w in _REANALYSIS_WRITE_TARGETS for w in writes):
        return True
    if tags.get("delegates"):
        return True
    if tags.get("is_initializer"):
        return True
    return False


def maybe_queue_reanalysis(
    session: Session,
    mc: MonitoredContract,
    event_type: str,
    data: dict | None = None,
) -> Job | None:
    """Queue a re-analysis job unless one is already in flight for the address and chain; return it or ``None``.

    Starts at ``discovery`` so cached static artifacts are copied and the static worker can detect implementation
    changes.
    """
    if not should_trigger_reanalysis(event_type, data):
        return None

    # Enrollment already excludes disabled chains, but a legacy row must never spawn work on one.
    if not chain_enabled(mc.chain):
        logger.info(
            "Skipping re-analysis: chain not enabled for this deployment",
            extra={"address": mc.address, "chain": mc.chain, "reason": "chain_not_enabled", "site": "reanalysis"},
        )
        return None

    in_flight_candidates = (
        session.execute(
            select(Job).where(
                func.lower(Job.address) == mc.address.lower(),
                Job.status.in_([JobStatus.queued, JobStatus.processing]),
                # A token-input retry cannot observe a changed implementation/state.
                Job.request["effects_resume_work_id"].astext.is_(None),
            )
        )
        .scalars()
        .all()
    )
    for candidate in in_flight_candidates:
        req = candidate.request if isinstance(candidate.request, dict) else {}
        if req.get("chain", "ethereum") == mc.chain:
            logger.info(
                "Skipping re-analysis for %s: job %s already in-flight (stage=%s)",
                mc.address,
                candidate.id,
                candidate.stage.value,
            )
            return None

    if event_type == "state_changed_poll":
        trigger = f"poll:{(data or {}).get('field', 'unknown')}"
    elif event_type.startswith("value_changed"):
        trigger = f"verified_read:{(data or {}).get('field', 'unknown')}"
    else:
        trigger = event_type

    # No pinned rpc_url: a direct provider URL is what let a 429 storm bypass eRPC.
    request_dict: dict = {
        "address": mc.address,
        "chain": mc.chain,
        "name": f"Re-analysis ({trigger})",
        "reanalysis_trigger": trigger,
    }
    if mc.protocol_id:
        request_dict["protocol_id"] = mc.protocol_id

    # Snapshot current state so the completion webhook can show a diff.
    snapshot = _build_snapshot(session, mc)
    if snapshot:
        request_dict["reanalysis_snapshot"] = snapshot

    job = create_job(session, request_dict)

    # The new job rewrites this protocol's planes, so dirty the score. Marked after ``create_job`` commits so it never
    # references a rolled-back job.
    if mc.protocol_id:
        from services.scoring.dirty import SCORE_DIRTY_REANALYSIS, mark_protocol_score_dirty

        if mark_protocol_score_dirty(session, mc.protocol_id, SCORE_DIRTY_REANALYSIS):
            try:
                session.commit()
            except Exception:
                # Best-effort: a failing mark must not sink the already-committed job.
                session.rollback()
                logger.warning(
                    "Re-analysis: protocol score dirty-mark commit failed for protocol %s",
                    mc.protocol_id,
                    exc_info=True,
                )

    logger.info(
        "Queued re-analysis job %s for %s (trigger: %s)",
        job.id,
        mc.address,
        trigger,
    )
    return job


def _build_snapshot(session: Session, mc: MonitoredContract) -> dict[str, Any]:
    snap: dict[str, Any] = {}
    if not mc.contract_id:
        return snap

    contract = session.get(Contract, mc.contract_id)
    if not contract:
        return snap

    snap["implementation"] = contract.implementation
    snap["admin"] = contract.admin

    summary = session.execute(
        select(ContractSummary).where(ContractSummary.contract_id == contract.id)
    ).scalar_one_or_none()
    if summary:
        snap["control_model"] = summary.control_model
        snap["is_pausable"] = summary.is_pausable

    fns = (
        session.execute(select(EffectiveFunction.function_name).where(EffectiveFunction.contract_id == contract.id))
        .scalars()
        .all()
    )
    snap["effective_functions"] = sorted(fns)

    owner_cv = (
        session.execute(
            select(ControllerValue).where(
                ControllerValue.contract_id == contract.id,
                ControllerValue.controller_id.in_(_OWNER_CONTROLLER_IDS),
            )
        )
        .scalars()
        .first()
    )
    if owner_cv:
        snap["owner"] = owner_cv.value

    return snap


def build_reanalysis_diff(session: Session, job: Job) -> list[str]:
    """Human-readable changes between the pre-reanalysis snapshot and current DB state."""
    request = job.request if isinstance(job.request, dict) else {}
    snapshot: dict[str, Any] = request.get("reanalysis_snapshot", {})
    if not snapshot:
        return []

    address = (job.address or "").lower()
    chain = request.get("chain", "ethereum")

    contract = (
        session.execute(
            select(Contract).where(
                func.lower(Contract.address) == address,
                Contract.chain == chain,
            )
        )
        .scalars()
        .first()
    )
    if not contract:
        return []

    changes: list[str] = []

    old_impl = snapshot.get("implementation")
    new_impl = contract.implementation
    if old_impl and new_impl and old_impl.lower() != new_impl.lower():
        changes.append(f"Implementation: `{old_impl}` → `{new_impl}`")
    elif not old_impl and new_impl:
        changes.append(f"Implementation: (none) → `{new_impl}`")

    old_admin = snapshot.get("admin")
    new_admin = contract.admin
    if old_admin and new_admin and old_admin.lower() != new_admin.lower():
        changes.append(f"Admin: `{old_admin}` → `{new_admin}`")

    summary = session.execute(
        select(ContractSummary).where(ContractSummary.contract_id == contract.id)
    ).scalar_one_or_none()
    if summary:
        old_model = snapshot.get("control_model")
        if old_model and summary.control_model and old_model != summary.control_model:
            changes.append(f"Control model: {old_model} → {summary.control_model}")

    old_fns = set(snapshot.get("effective_functions", []))
    new_fns_rows = (
        session.execute(select(EffectiveFunction.function_name).where(EffectiveFunction.contract_id == contract.id))
        .scalars()
        .all()
    )
    new_fns = set(new_fns_rows)
    added = sorted(new_fns - old_fns)
    removed = sorted(old_fns - new_fns)
    if added or removed:
        parts = [f"Functions: {len(old_fns)} → {len(new_fns)}"]
        if added:
            parts.append(f"+{', '.join(added)}")
        if removed:
            parts.append(f"-{', '.join(removed)}")
        changes.append(" | ".join(parts))

    old_owner = snapshot.get("owner")
    owner_cv = (
        session.execute(
            select(ControllerValue).where(
                ControllerValue.contract_id == contract.id,
                ControllerValue.controller_id.in_(_OWNER_CONTROLLER_IDS),
            )
        )
        .scalars()
        .first()
    )
    new_owner = owner_cv.value if owner_cv else None
    if old_owner and new_owner and old_owner.lower() != new_owner.lower():
        changes.append(f"Owner: `{old_owner}` → `{new_owner}`")

    return changes
