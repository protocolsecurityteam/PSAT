
from __future__ import annotations

from datetime import datetime, timezone

from tests.live.conftest import LiveClient, _parse_dt

WEDGE_THRESHOLD_SECONDS = 20 * 60


def test_no_wedged_jobs(live_client: LiveClient):
    now = datetime.now(timezone.utc)
    stuck = []
    for job in live_client.jobs():
        if job.get("status") != "processing":
            continue
        updated_at = job.get("updated_at")
        if not updated_at:
            continue
        try:
            updated = _parse_dt(updated_at)
        except (ValueError, TypeError):
            stuck.append(job)
            continue
        age = (now - updated).total_seconds()
        if age > WEDGE_THRESHOLD_SECONDS:
            stuck.append(job)

    assert not stuck, (
        "jobs stuck in processing > "
        f"{WEDGE_THRESHOLD_SECONDS // 60} min: "
        f"{[(j.get('job_id'), j.get('stage'), j.get('updated_at')) for j in stuck]}"
    )
