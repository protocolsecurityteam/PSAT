"""During ``parallel_map`` the main session sits idle for minutes and Neon closes its SSL connection, so a heartbeat
on it fails silently and the stale sweep requeues live work (psat-pr-73, ``ResolutionWorker-657-2655967e``).
``pool_pre_ping=True`` replaces stale connections on the fresh session's checkout.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

from db.models import JobStage, JobStatus


def _make_job(**overrides):
    defaults = dict(
        id=uuid.uuid4(),
        address="0x" + "a" * 40,
        name="test-job",
        status=JobStatus.processing,
        stage=JobStage.discovery,
        updated_at=datetime.now(timezone.utc),
        worker_id="some-worker",
        detail=None,
        retry_count=0,
        lease_id=uuid.uuid4(),
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)
