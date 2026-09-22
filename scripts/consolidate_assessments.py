"""Consolidate existing analytical artifacts with old workers stopped.

Run ``python -m scripts.consolidate_assessments --dry-run`` before the write run.
Each job is copied, read back, and compared before its old artifact rows are
removed. Existing Assessment sections must match, so interrupted runs are safe
to retry and conflicting newer results are never overwritten. Object storage
objects for old rows are retained for backup/rollback; this does not GC blobs.
"""

from __future__ import annotations

import argparse
import copy
from typing import Any

from sqlalchemy import delete, or_, select
from sqlalchemy.orm import Session

from db.assessment import load_assessment, store_assessment
from db.models import Artifact, ContractMaterialization, Job, SessionLocal
from db.queue import _artifact_row_to_value
from db.queue._chains import _job_chain_name
from schemas.assessment import ASSESSMENT_SECTIONS, validate_assessment
from scripts.consolidate_materializations import SOURCE_ANALYSIS_SCHEMA_VERSION, TARGET_ANALYSIS_SCHEMA_VERSION

_NESTED_SECTIONS = {"snapshot": "control_snapshot", "effective_permissions": "effective_permissions"}
_STATIC_SECTIONS = ("contract_analysis", "control_tracking_plan", "predicate_trees", "effects")


def _legacy_filter():
    return or_(Artifact.name.in_(ASSESSMENT_SECTIONS), Artifact.name.startswith("recursive."))


def _merge_section(target: dict[str, Any], name: str, value: Any) -> None:
    if name in target and target[name] != value:
        raise ValueError(f"Existing Assessment section conflicts with legacy artifact: {name}")
    target[name] = value


def _hydrate_recursive_static_sections(session: Session, job: Job, assessment: dict[str, Any]) -> None:
    """Make migrated recursive children self-contained from converted caches."""
    from db import contract_materializations as cm

    recursive = assessment.get("recursive")
    if not isinstance(recursive, dict):
        return
    chain = _job_chain_name(job)
    for address, child in recursive.items():
        if not isinstance(child, dict) or all(isinstance(child.get(name), dict) for name in _STATIC_SECTIONS):
            continue
        materialization = cm.find_by_address(session, chain=chain, address=address)
        if materialization is None:
            unconverted_v6 = session.execute(
                select(ContractMaterialization).where(
                    ContractMaterialization.chain == cm.chain_cache_token(chain),
                    ContractMaterialization.address == address.lower(),
                    ContractMaterialization.status == "ready",
                    ContractMaterialization.analysis_schema_version == SOURCE_ANALYSIS_SCHEMA_VERSION,
                )
            ).scalar_one_or_none()
            if unconverted_v6 is not None:
                raise RuntimeError(
                    "Ready version-6 contract materialization has not been converted; "
                    "run scripts.consolidate_materializations before scripts.consolidate_assessments "
                    f"(chain={chain}, address={address.lower()})"
                )
            continue
        cached = cm.hydrate_assessment(materialization)
        if cached is None:
            continue
        for name in _STATIC_SECTIONS:
            value = cached.get(name)
            if name not in child and isinstance(value, dict):
                child[name] = copy.deepcopy(value)


def consolidate_job(session: Session, job_id: Any, *, dry_run: bool = False) -> int:
    """Return the number of legacy rows verified and consolidated for one job."""
    from db import contract_materializations as cm

    if cm.ANALYSIS_SCHEMA_VERSION != TARGET_ANALYSIS_SCHEMA_VERSION:
        raise RuntimeError(
            "job Assessment cutover is pinned to analysis schema version "
            f"{TARGET_ANALYSIS_SCHEMA_VERSION}, runtime is {cm.ANALYSIS_SCHEMA_VERSION}"
        )
    job = session.execute(select(Job).where(Job.id == job_id).with_for_update()).scalar_one()
    rows = session.execute(select(Artifact).where(Artifact.job_id == job_id, _legacy_filter())).scalars().all()
    if not rows:
        session.rollback()
        return 0
    assessment: dict[str, Any] = copy.deepcopy(
        dict(load_assessment(session, job_id) or {"schema_version": "assessment/1"})
    )
    for row in rows:
        body = _artifact_row_to_value(row)  # A missing/unreadable body aborts; never silently drop it.
        if row.name in ASSESSMENT_SECTIONS:
            _merge_section(assessment, row.name, body)
        else:
            parts = row.name.split(".", 2)
            if len(parts) != 3 or parts[2] not in _NESTED_SECTIONS:
                raise ValueError(f"Unrecognized recursive artifact: {row.name}")
            nested = assessment.setdefault("recursive", {}).setdefault(
                parts[1].lower(), {"schema_version": "assessment/1"}
            )
            _merge_section(nested, _NESTED_SECTIONS[parts[2]], body)
    _hydrate_recursive_static_sections(session, job, assessment)
    validated = validate_assessment(assessment)
    if dry_run:
        session.rollback()
        return len(rows)
    row_ids = [row.id for row in rows]
    store_assessment(session, job_id, validated)
    if load_assessment(session, job_id) != assessment:
        raise RuntimeError(f"Assessment read-back mismatch for job {job_id}; legacy rows retained")
    if (
        job.analysis_schema_version == SOURCE_ANALYSIS_SCHEMA_VERSION
        and TARGET_ANALYSIS_SCHEMA_VERSION == 7
        and all(isinstance(assessment.get(name), dict) for name in _STATIC_SECTIONS)
    ):
        job.analysis_schema_version = TARGET_ANALYSIS_SCHEMA_VERSION
    session.execute(delete(Artifact).where(Artifact.id.in_(row_ids)))
    session.commit()
    return len(row_ids)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--job-id", help="Restrict the cutover to one job")
    args = parser.parse_args(argv)
    with SessionLocal() as session:
        query = select(Artifact.job_id).where(_legacy_filter()).distinct().order_by(Artifact.job_id)
        if args.job_id:
            query = query.where(Artifact.job_id == args.job_id)
        job_ids = list(session.execute(query).scalars())
        session.rollback()
        count = 0
        for job_id in job_ids:
            count += consolidate_job(session, job_id, dry_run=args.dry_run)
    print(
        f"{'Validated' if args.dry_run else 'Consolidated'} {count} analytical artifact rows across {len(job_ids)} jobs"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
