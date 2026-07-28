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


# State-variable write targets whose mutation invalidates the control
# graph / effective permissions / implementation hash and so warrants a
# full re-analysis job. Anything writing one of these slots — Compound
# NewAdmin, Curve CommitOwnership, Solady setOwner, a fork's renamed
# admin field — triggers reanalysis through the tag-driven path.
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

# Field names whose poll-detected change always triggers reanalysis
# regardless of the per-contract write-target set. ``implementation`` is
# the canonical proxy-upgrade signal and the vendored EIP-1967 poll
# entry surfaces it without ever flowing through ``_REANALYSIS_WRITE_
# TARGETS``; included here so the trigger fires even when the proxy
# shell has no tracking plan of its own.
REANALYSIS_POLL_FIELDS_VENDORED = frozenset({"implementation"})


def should_trigger_reanalysis(event_type: str, data: dict | None = None) -> bool:
    """Return True if *event_type* (with optional *data*) warrants a re-analysis.

    Tag-driven: an event triggers reanalysis when its ``effect_tags`` say
    the emitter wrote a control-relevant slot, performed a delegatecall
    (delegate-target swap), or ran through the OZ Initializable modifier.
    Bare event_type calls (legacy tests, queue dedupe paths) synthesize
    tags from the canonical event_type via
    ``_HANDROLLED_EVENT_TYPE_TO_TAGS`` so the dispatch shape is uniform.

    The poll path (``state_changed_poll``) reuses the same write-target
    vocabulary so custom slots (``protocolAdmin``, a renamed ``_admin``)
    trigger reanalysis through the analyzer-derived polling plan
    without a per-slot map entry. ``implementation`` is additionally
    treated as a vendored trigger because it's emitted by the EIP-1967
    storage-slot poll entry, which is keyed by ``proxy_type`` rather
    than by the analyzer's write targets.
    """
    if event_type == "state_changed_poll" and data:
        field = data.get("field")
        if field in REANALYSIS_POLL_FIELDS_VENDORED:
            return True
        if isinstance(field, str) and field in _REANALYSIS_WRITE_TARGETS:
            return True
        return False

    # Tag-driven dispatch. Prefer tags from the parsed event; fall back
    # to canonical-event_type synthesis for callers that pass bare
    # event_type without a data envelope.
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
    """Queue a re-analysis job if the event warrants it.

    Checks:
    1. Event type is in the trigger set.
    2. No queued or processing job already exists for this address+chain.

    The job starts at the ``discovery`` stage so the caching system can
    copy static artifacts (source files, contract_analysis, etc.) and the
    static worker can detect implementation changes via
    ``_check_proxy_cache``.

    Returns the created :class:`Job`, or ``None`` if skipped.
    """
    if not should_trigger_reanalysis(event_type, data):
        return None

    # Defense in depth (inv. 14): enrollment already gates off-allowlist chains, so
    # a monitored contract on a disabled chain should not exist going forward — but
    # a legacy row must never re-spawn analysis work on a chain this deployment has
    # disabled.
    if not chain_enabled(mc.chain):
        logger.info(
            "Skipping re-analysis: chain not enabled for this deployment",
            extra={"address": mc.address, "chain": mc.chain, "reason": "chain_not_enabled", "site": "reanalysis"},
        )
        return None

    # Deduplicate: skip if a job is already in-flight for this address+chain.
    in_flight_candidates = (
        session.execute(
            select(Job).where(
                func.lower(Job.address) == mc.address.lower(),
                Job.status.in_([JobStatus.queued, JobStatus.processing]),
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

    # Determine a human-readable trigger label
    if event_type == "state_changed_poll":
        trigger = f"poll:{(data or {}).get('field', 'unknown')}"
    else:
        trigger = event_type

    # No rpc_url is pinned here: the worker resolves eRPC from ``chain`` so
    # re-analysis routes through the proxy like every other run. Pinning a
    # direct provider URL is what let a 429 storm bypass eRPC.
    request_dict: dict = {
        "address": mc.address,
        "chain": mc.chain,
        "name": f"Re-analysis ({trigger})",
        "reanalysis_trigger": trigger,
    }
    if mc.protocol_id:
        request_dict["protocol_id"] = mc.protocol_id

    # Snapshot current analysis state so the completion webhook can show a diff.
    snapshot = _build_snapshot(session, mc)
    if snapshot:
        request_dict["reanalysis_snapshot"] = snapshot

    job = create_job(session, request_dict)

    logger.info(
        "Queued re-analysis job %s for %s (trigger: %s)",
        job.id,
        mc.address,
        trigger,
    )
    return job


# ---------------------------------------------------------------------------
# Snapshot & diff helpers
# ---------------------------------------------------------------------------


def _build_snapshot(session: Session, mc: MonitoredContract) -> dict[str, Any]:
    """Capture the current analysis state for later comparison."""
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

    # Effective function names
    fns = (
        session.execute(select(EffectiveFunction.function_name).where(EffectiveFunction.contract_id == contract.id))
        .scalars()
        .all()
    )
    snap["effective_functions"] = sorted(fns)

    # Owner value
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
    """Compare the pre-reanalysis snapshot with the current DB state.

    Returns a list of human-readable change descriptions (may be empty).
    """
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

    # Implementation
    old_impl = snapshot.get("implementation")
    new_impl = contract.implementation
    if old_impl and new_impl and old_impl.lower() != new_impl.lower():
        changes.append(f"Implementation: `{old_impl}` → `{new_impl}`")
    elif not old_impl and new_impl:
        changes.append(f"Implementation: (none) → `{new_impl}`")

    # Admin
    old_admin = snapshot.get("admin")
    new_admin = contract.admin
    if old_admin and new_admin and old_admin.lower() != new_admin.lower():
        changes.append(f"Admin: `{old_admin}` → `{new_admin}`")

    # Summary fields
    summary = session.execute(
        select(ContractSummary).where(ContractSummary.contract_id == contract.id)
    ).scalar_one_or_none()
    if summary:
        old_model = snapshot.get("control_model")
        if old_model and summary.control_model and old_model != summary.control_model:
            changes.append(f"Control model: {old_model} → {summary.control_model}")

    # Effective functions diff
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

    # Owner
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
