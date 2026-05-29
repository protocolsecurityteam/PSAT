"""Fleet / process-status endpoint.

Thin wrapper over ``services.aggregations.build_fleet_status`` (where the
query logic lives, mirroring the other ``build_*`` aggregations). Backs the
monitor page's "all processes" view: the jobs-queue pipeline, the
heartbeat-backed row-draining daemons, and the runtime watchers.

Read-only, same access posture as ``/api/stats`` and ``/api/jobs``.
Frontend wiring is deferred — this just guarantees the data is queryable.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter

from services.aggregations import build_fleet_status

from . import deps

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/api/fleet")
def fleet_status() -> dict[str, Any]:
    """Liveness + work breakdown for every background process."""
    with deps.SessionLocal() as session:
        return build_fleet_status(session)
