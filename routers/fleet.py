"""Fleet / process-status endpoint.

Thin wrapper over ``services.aggregations.build_fleet_status`` (where the
query logic lives, mirroring the other ``build_*`` aggregations). Backs the
monitor page's "all processes" view: the jobs-queue pipeline, the
heartbeat-backed row-draining daemons, and the runtime watchers.

Admin-gated, same access posture as ``/api/stats`` and ``/api/jobs``: an
operator view of internal process health, not part of the public surface.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends

from services.aggregations import build_fleet_status

from . import deps

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/api/fleet", dependencies=[Depends(deps.require_admin_key)])
def fleet_status() -> dict[str, Any]:
    """Liveness + work breakdown for every background process."""
    with deps.SessionLocal() as session:
        return build_fleet_status(session)
