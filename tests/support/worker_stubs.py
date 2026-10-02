import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

from db.models import JobStage, JobStatus
from workers.base import BaseWorker


class _TestWorker(BaseWorker):
    stage = JobStage.discovery
    next_stage = JobStage.static
    poll_interval = 0  # no real sleeping in tests

    def process(self, session, job):
        pass


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
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)
