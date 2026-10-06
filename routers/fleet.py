"""Fleet status endpoint; logic in ``services.aggregations.build_fleet_status``. Admin-gated."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends

from schemas.api_responses import FleetStatusResponse
from services.aggregations import build_fleet_status

from . import deps

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/api/fleet", dependencies=[Depends(deps.require_admin)], response_model=None)
def fleet_status() -> FleetStatusResponse:
    with deps.SessionLocal() as session:
        return build_fleet_status(session)
