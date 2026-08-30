"""Backfill canonical ``assessment`` artifacts from historical pipeline facts.

Dry-run is the default. Pass ``--write`` to persist. Existing assessments are
left untouched unless ``--force`` is supplied, making the command idempotent and
safe to resume after a partial run.

Usage::

    uv run python -m scripts.backfill_assessments
    uv run python -m scripts.backfill_assessments --write --limit 100
    uv run python -m scripts.backfill_assessments --write --force
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Any

from pydantic import TypeAdapter
from sqlalchemy import select

from db.models import Contract, EffectiveFunction, EffectVerdict, Job, SessionLocal, derive_job_chain_id
from db.queue import get_artifact, store_artifact
from schemas.assessment import Assessment
from services.assessment import add_effects, add_observations, add_policy, add_resolution, build_static_assessment
from utils.logging import configure_logging

logger = logging.getLogger(__name__)
_ADAPTER = TypeAdapter(Assessment)


def _chain_id(job: Job) -> int:
    if isinstance(job.chain_id, int):
        return job.chain_id
    request = job.request if isinstance(job.request, dict) else {}
    return derive_job_chain_id(request.get("chain"), job.address) or 1


def _dict_artifact(session, job_id: Any, name: str) -> dict[str, Any] | None:
    value = get_artifact(session, job_id, name)
    return value if isinstance(value, dict) else None


def _effect_rows(session, job: Job) -> tuple[list[EffectVerdict], dict[int, str]]:
    contract = session.execute(select(Contract).where(Contract.job_id == job.id).limit(1)).scalar_one_or_none()
    if contract is None:
        return [], {}
    functions = list(
        session.execute(select(EffectiveFunction).where(EffectiveFunction.contract_id == contract.id)).scalars()
    )
    function_ids = [function.id for function in functions]
    if not function_ids:
        return [], {}
    verdicts = list(session.execute(select(EffectVerdict).where(EffectVerdict.function_id.in_(function_ids))).scalars())
    signatures = {function.id: function.abi_signature or function.function_name for function in functions}
    return verdicts, signatures


def build_historical_assessment(session, job: Job) -> Assessment | None:
    """Translate one historical job, returning ``None`` without an address."""

    if not isinstance(job.address, str) or not job.address:
        return None
    analysis = _dict_artifact(session, job.id, "contract_analysis")
    if analysis is None:
        return None
    subject = analysis.get("subject")
    subject = subject if isinstance(subject, dict) else {}
    effects = _dict_artifact(session, job.id, "effects") or {
        "schema_version": "missing",
        "error": "historical effects artifact missing",
    }
    trees = _dict_artifact(session, job.id, "predicate_trees") or {
        "schema_version": "missing",
        "error": "historical predicate_trees artifact missing",
    }
    assessment = build_static_assessment(
        chain_id=_chain_id(job),
        address=str(subject.get("address") or job.address),
        contract_name=str(subject.get("name") or job.name or "Contract"),
        code_hash=None,
        source_hash=job.source_content_hash,
        analysis=analysis,
        effects=effects,
        predicate_trees=trees,
    )
    snapshot = _dict_artifact(session, job.id, "control_snapshot")
    if snapshot is not None:
        assessment = add_observations(assessment, snapshot)
    graph = _dict_artifact(session, job.id, "resolved_control_graph")
    if graph is not None:
        assessment = add_resolution(assessment, graph, chain_id=_chain_id(job))
    permissions = _dict_artifact(session, job.id, "effective_permissions")
    if permissions is not None:
        assessment = add_policy(assessment, permissions, chain_id=_chain_id(job))
    verdicts, signatures = _effect_rows(session, job)
    if verdicts:
        assessment = add_effects(assessment, verdicts, signatures_by_function_row=signatures)
    _ADAPTER.validate_python(assessment)
    return assessment


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="Persist assessment artifacts; default is dry-run.")
    parser.add_argument("--force", action="store_true", help="Rebuild jobs that already have an assessment.")
    parser.add_argument("--limit", type=int, default=None, help="Maximum address-scoped jobs to inspect.")
    args = parser.parse_args(argv)
    configure_logging()

    scanned = built = skipped = failed = 0
    with SessionLocal() as session:
        stmt = select(Job).where(Job.address.isnot(None)).order_by(Job.created_at, Job.id)
        if isinstance(args.limit, int) and args.limit > 0:
            stmt = stmt.limit(args.limit)
        for job in session.execute(stmt).scalars():
            scanned += 1
            if not args.force and get_artifact(session, job.id, "assessment") is not None:
                skipped += 1
                continue
            try:
                assessment = build_historical_assessment(session, job)
                if assessment is None:
                    skipped += 1
                    continue
                if args.write:
                    store_artifact(session, job.id, "assessment", data=assessment)
                built += 1
            except Exception as exc:
                session.rollback()
                failed += 1
                logger.warning(
                    "assessment backfill failed for job %s",
                    job.id,
                    extra={"exc_type": type(exc).__name__, "job_id": str(job.id)},
                )

    logger.info(
        "assessment backfill complete: scanned=%d built=%d skipped=%d failed=%d write=%s",
        scanned,
        built,
        skipped,
        failed,
        args.write,
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
