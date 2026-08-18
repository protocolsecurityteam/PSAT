"""MonitoredContract listing and updates + MonitoredEvent listing."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select

from db.models import Contract, MonitoredContract, MonitoredEvent, Protocol
from schemas.api_requests import UpdateMonitoredContractRequest, UpsertMonitoredContractRequest
from services.monitoring.chain_rpc import chain_id_for, rpc_for_chain
from services.monitoring.tracking_plan_state import CONFIG_SUPPLIED_BY_CALLER, preserve_scan_plane_facts
from utils.chains import UnsupportedChainError, require_supported_chain
from utils.rpc import rpc_request

from . import deps

logger = logging.getLogger(__name__)

router = APIRouter()


def _current_head_block(chain: str | None) -> int | None:
    """Current head on the enrolled contract's OWN chain, used to seed a
    manually-added contract's scan cursor and enrollment floor. ``None`` when
    the read did not answer.

    ``chain`` selects the RPC route: mainnet (and any unresolvable chain) keeps
    ``deps.DEFAULT_RPC_URL`` verbatim, a second chain resolves its own eRPC route
    from the registry (same ``rpc_for_chain`` the scanner uses). Without this a
    non-mainnet enrollment seeded ``enrollment_block`` from the MAINNET head — a
    wrong, immutable pre-watch floor.

    A failed read is not-determined and block 0 is not its stand-in: it seeds a
    cursor claiming the whole chain as backlog and a floor that licenses every
    historical event as live. The caller refuses the enrollment instead (same
    rule as ``enrollment._block_for``)."""
    try:
        return int(
            rpc_request(
                rpc_for_chain(chain, deps.DEFAULT_RPC_URL),
                "eth_blockNumber",
                [],
                chain_id=chain_id_for(chain),
            ),
            16,
        )
    except Exception as exc:
        logger.warning(
            "Could not read head block for monitoring upsert: %s",
            exc,
            extra={"exc_type": type(exc).__name__, "chain": chain, "reason": "head_read_not_determined"},
        )
        return None


#: Stamped into every caller-supplied ``monitoring_config``. The auto-enrollment
#: path (``services/monitoring/enrollment._build_monitoring_config``) always
#: emits a positive tracking-plan token: ``tracked_topics`` present = the plan
#: was read (a non-empty list is the witnessed plan, ``[]`` the witnessed
#: read-and-named-nothing finding); ``tracking_plan_not_determined`` present =
#: the plan was not read and the reason token says why. A config authored by an
#: API caller has none of that provenance, and storing it verbatim with neither
#: key would read as a builder output that never existed. This token is the
#: honest answer for the caller-authored case and keeps the builder's states
#: earned; NEITHER key survives only on rows that predate the discriminant.
CALLER_SUPPLIED_TRACKING_PLAN = CONFIG_SUPPLIED_BY_CALLER


def _stamp_caller_supplied(
    monitoring_config: dict[str, Any] | None,
    existing_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The stored config for a caller-authored enrollment, provenance-stamped.

    The route OWNS ``tracking_plan_not_determined`` here: a caller value is
    overwritten, not merged, so the token cannot be forged into asserting some
    analyzer reason (``plan_not_readable``, ``contract_not_analyzed``, …) for a
    config no analyzer produced. Overwriting rather than rejecting also keeps a
    read-modify-write of an already-stamped row working.

    The two analyzer-owned keys — ``tracked_topics`` and ``polling_plan`` — are
    rejected upstream in ``schemas.api_requests`` rather than dropped here: each
    drives the monitor on the wire, so silently discarding one would tell the
    caller their topics are being scanned / their slots polled. The stamp cannot
    substitute for that rejection: it marks the CONFIG's provenance, while the
    event a caller-authored ``polling_plan`` would mint carries none.

    *existing_config* supplies the row's scan-plane record (``scan_gaps``),
    which is carried across the overwrite: it states which block intervals this
    row's scanner never covered, and no caller authored it. Dropping it would
    let the row present continuous coverage over an interval nothing read.
    """
    stamped = dict(monitoring_config or {})
    stamped["tracking_plan_not_determined"] = CALLER_SUPPLIED_TRACKING_PLAN
    return preserve_scan_plane_facts(stamped, existing_config)


def _monitored_contract_payload(c: MonitoredContract) -> dict[str, Any]:
    return {
        "id": str(c.id),
        "address": c.address,
        "chain": c.chain,
        "protocol_id": c.protocol_id,
        "contract_id": c.contract_id,
        "contract_type": c.contract_type,
        "monitoring_config": c.monitoring_config,
        "last_known_state": c.last_known_state,
        "last_poll_status": c.last_poll_status,
        "last_scanned_block": c.last_scanned_block,
        "enrollment_block": c.enrollment_block,
        "needs_polling": c.needs_polling,
        "is_active": c.is_active,
        "enrollment_source": c.enrollment_source,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
    }


@router.get("/api/monitored-contracts")
def list_monitored_contracts(
    protocol_id: int | None = None,
    chain: str | None = None,
) -> list[dict[str, Any]]:
    """List all MonitoredContract rows, optionally filtered."""
    with deps.SessionLocal() as session:
        stmt = select(MonitoredContract).order_by(MonitoredContract.created_at.desc())
        if protocol_id is not None:
            stmt = stmt.where(MonitoredContract.protocol_id == protocol_id)
        if chain is not None:
            stmt = stmt.where(MonitoredContract.chain == chain)
        contracts = session.execute(stmt).scalars().all()
        return [_monitored_contract_payload(c) for c in contracts]


@router.post("/api/protocols/{protocol_id}/monitoring", dependencies=[Depends(deps.require_admin_key)])
def upsert_protocol_monitoring(protocol_id: int, request: UpsertMonitoredContractRequest) -> dict[str, Any]:
    """Create or update one monitored contract for a protocol."""
    # Allowlist enforcement (inv. 14): enrolling a contract on a chain takes
    # scanner leases and RPC on that chain, so a chain this deployment has not
    # enabled is rejected here (the default 'ethereum' is supported everywhere).
    try:
        require_supported_chain(chain=request.chain, context="monitored-contract enrollment")
    except UnsupportedChainError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    with deps.SessionLocal() as session:
        protocol = session.get(Protocol, protocol_id)
        if protocol is None:
            raise HTTPException(status_code=404, detail="Protocol not found")

        contract_stmt = select(Contract).where(
            Contract.protocol_id == protocol_id,
            func.lower(Contract.address) == request.address.lower(),
        )
        if request.chain:
            contract_stmt = contract_stmt.where(Contract.chain == request.chain)
        contract = session.execute(contract_stmt).scalar_one_or_none()

        existing = session.execute(
            select(MonitoredContract).where(
                func.lower(MonitoredContract.address) == request.address.lower(),
                MonitoredContract.chain == request.chain,
            )
        ).scalar_one_or_none()

        if existing is None:
            # Start watching from the current head, not block 0: this is a
            # "monitor from now on" add, so scanning from 0 would replay years
            # of history. enrollment_block records the same head as the floor
            # below which the scanner records events as pre-watch history
            # without notifying (consistent with the auto-enrollment inserts).
            head_block = _current_head_block(request.chain)
            if head_block is None:
                raise HTTPException(
                    status_code=503,
                    detail="Chain head not determined; cannot seed a scan cursor or enrollment floor. Retry.",
                )
            existing = MonitoredContract(
                address=request.address,
                chain=request.chain,
                protocol_id=protocol_id,
                contract_id=contract.id if contract else None,
                contract_type=request.contract_type,
                monitoring_config=_stamp_caller_supplied(request.monitoring_config),
                last_known_state={},
                last_scanned_block=head_block,
                enrollment_block=head_block,
                needs_polling=request.needs_polling,
                is_active=request.is_active,
                enrollment_source="surface_alert",
            )
            session.add(existing)
        else:
            existing.protocol_id = protocol_id
            existing.contract_id = contract.id if contract else existing.contract_id
            existing.contract_type = request.contract_type
            existing.monitoring_config = _stamp_caller_supplied(request.monitoring_config, existing.monitoring_config)
            existing.needs_polling = request.needs_polling
            existing.is_active = request.is_active
            existing.enrollment_source = existing.enrollment_source or "surface_alert"

        session.commit()
        session.refresh(existing)
        deps.log_admin_mutation("monitoring_upsert", id=str(existing.id), protocol_id=protocol_id)
        return _monitored_contract_payload(existing)


@router.patch("/api/monitored-contracts/{contract_id}", dependencies=[Depends(deps.require_admin_key)])
def update_monitored_contract(contract_id: str, request: UpdateMonitoredContractRequest) -> dict[str, Any]:
    """Update monitoring_config, is_active, or needs_polling on a MonitoredContract."""
    try:
        parsed = uuid.UUID(contract_id)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=404, detail="MonitoredContract not found") from exc
    with deps.SessionLocal() as session:
        mc = session.get(MonitoredContract, parsed)
        if mc is None:
            raise HTTPException(status_code=404, detail="MonitoredContract not found")

        if request.monitoring_config is not None:
            mc.monitoring_config = _stamp_caller_supplied(request.monitoring_config, mc.monitoring_config)
        if request.is_active is not None:
            mc.is_active = request.is_active
        if request.needs_polling is not None:
            mc.needs_polling = request.needs_polling

        session.commit()
        session.refresh(mc)
        deps.log_admin_mutation("monitored_contract_update", id=str(mc.id))
        return _monitored_contract_payload(mc)


@router.get("/api/monitored-events")
def list_monitored_events(
    contract_id: str | None = None,
    address: str | None = None,
    chain: str | None = None,
    event_type: str | None = None,
    limit: int = Query(default=50, ge=1, le=500),
) -> list[dict[str, Any]]:
    """List MonitoredEvent rows, optionally filtered.

    Filter modes (apply additively):
      - ``contract_id``: by MonitoredContract.id (uuid)
      - ``address`` (+ optional ``chain``): resolves to monitored_contract_id
        on the fly so the front-end can query by address — useful for
        rendering a Safe/Timelock 'recent activity' panel without first
        having to look up the MonitoredContract row.
      - ``event_type``: filter to a single event_type
    """
    parsed_contract_id: uuid.UUID | None = None
    if contract_id is not None:
        try:
            parsed_contract_id = uuid.UUID(contract_id)
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=422, detail="contract_id is not a valid UUID") from exc
    with deps.SessionLocal() as session:
        # Multi-key sort. detected_at desc is the primary axis, but the
        # column has a now()-default that ties events written in the
        # same scan pass — so block_number desc disambiguates within a
        # tie (newer-block-first matches the recency story). id desc
        # is the final fallback purely for *deterministic* output —
        # MonitoredEvent.id is a UUIDv4 and carries no insertion or
        # log-order semantics, but a deterministic tiebreaker beats
        # exposing arbitrary DB scan order to clients.
        # If exact log-order ever becomes user-visible (e.g. step #4c
        # historical backfill rendering each batch CallScheduled
        # individually), promote log_index from the data JSON to a
        # real column and sort on it before id.
        stmt = (
            select(MonitoredEvent)
            .order_by(
                MonitoredEvent.detected_at.desc(),
                MonitoredEvent.block_number.desc(),
                MonitoredEvent.id.desc(),
            )
            .limit(limit)
        )
        if parsed_contract_id is not None:
            stmt = stmt.where(MonitoredEvent.monitored_contract_id == parsed_contract_id)
        # address and/or chain — resolve to a set of MonitoredContract ids
        # then narrow events. Either filter alone is supported; together
        # they intersect at the contract level. Without either, we don't
        # touch the contracts table.
        if address is not None or chain is not None:
            mc_q = select(MonitoredContract.id)
            if address is not None:
                mc_q = mc_q.where(MonitoredContract.address == address.lower())
            if chain is not None:
                mc_q = mc_q.where(MonitoredContract.chain == chain)
            mc_ids = session.execute(mc_q).scalars().all()
            if not mc_ids:
                # No matching MonitoredContract → no events to return.
                # Avoids scanning the events table when the answer is
                # structurally empty.
                return []
            stmt = stmt.where(MonitoredEvent.monitored_contract_id.in_(mc_ids))
        if event_type is not None:
            stmt = stmt.where(MonitoredEvent.event_type == event_type)
        events = session.execute(stmt).scalars().all()
        return [
            {
                "id": str(e.id),
                "monitored_contract_id": str(e.monitored_contract_id),
                "event_type": e.event_type,
                "block_number": e.block_number,
                "tx_hash": e.tx_hash,
                "data": e.data,
                "detected_at": e.detected_at.isoformat() if e.detected_at else None,
            }
            for e in events
        ]
