"""Queue bounded re-analysis for monitored contracts without a current materialization.

Bumping ``ANALYSIS_SCHEMA_VERSION`` turns every row into a miss and the fleet silently drops to baseline watching; this
rebuilds at a chosen rate. Daily cap ``PSAT_MATERIALIZATION_REBUILD_BUDGET_PER_DAY`` (default 25, 0 disables); jobs
issued in the last 24h count against it and the remainder is reported. ``status='building'`` rows are excluded.

Dry run by default::

    uv run python -m scripts.reconcile_materializations
    uv run python -m scripts.reconcile_materializations --budget 5 --apply
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from sqlalchemy.orm import Session

from db.models import SessionLocal
from db.queue import create_job
from services.monitoring.materialization_reconciler import (
    REBUILD_REQUEST_KEY,
    RebuildCandidate,
    plan_rebuilds,
)
from utils.chains import chain_enabled
from utils.logging import configure_logging

logger = logging.getLogger(__name__)


def queue_rebuilds(session: Session, candidates: list[RebuildCandidate]) -> dict[str, int]:
    """One re-analysis job per candidate, chain-gated like ``maybe_queue_reanalysis``.

    ``force`` is required: the static cache isn't version-gated, so after a schema bump a rebuild would copy the old
    artifacts and clear the backlog without re-analyzing anything.
    """
    counts = {"queued": 0, "skipped_chain_not_enabled": 0}
    for candidate in candidates:
        if not chain_enabled(candidate.chain):
            counts["skipped_chain_not_enabled"] += 1
            continue
        request: dict = {
            "address": candidate.address,
            "chain": candidate.chain,
            "name": f"Materialization rebuild ({candidate.reason})",
            "force": True,
            REBUILD_REQUEST_KEY: True,
        }
        if candidate.protocol_id:
            request["protocol_id"] = candidate.protocol_id
        job = create_job(session, request)
        logger.info(
            "queued materialization rebuild job %s for %s (%s, %s)",
            job.id,
            candidate.address,
            candidate.chain,
            candidate.reason,
        )
        counts["queued"] += 1
    return counts


def format_table(candidates: list[RebuildCandidate]) -> str:
    if not candidates:
        return "no rebuilds within budget"
    header = f"{'address':<44}{'chain':<10}{'reason':<22}{'protocol':>9}"
    lines = [header, "-" * len(header)]
    for c in candidates:
        lines.append(f"{c.address:<44}{c.chain:<10}{c.reason:<22}{(c.protocol_id if c.protocol_id else '-'):>9}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="Queue the jobs. Off by default (dry run reports only).")
    ap.add_argument(
        "--budget",
        type=int,
        default=None,
        help="Override the daily cap for this run (still net of jobs already queued in the last 24h).",
    )
    args = ap.parse_args(argv)

    configure_logging()

    with SessionLocal() as session:
        candidates, backlog = plan_rebuilds(session, budget=args.budget)
        print(json.dumps(backlog, indent=2, sort_keys=True))
        print()
        print(format_table(candidates))
        if not args.apply:
            print(f"\ndry run: {len(candidates)} rebuild job(s) would be queued. Re-run with --apply to queue.")
            return 0
        counts = queue_rebuilds(session, candidates)
        print("\napplied: " + json.dumps(counts, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
