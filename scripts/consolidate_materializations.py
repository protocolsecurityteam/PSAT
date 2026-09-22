"""Release-time conversion of v6 materializations to ``assessment/1``.

Run this after old writers are stopped and before deploying readers which
require materialization era 7. The command is restartable and lossless:

* only ready v6 rows are candidates;
* legacy inline/blob component payloads remain untouched as backups;
* the new Assessment is read back and compared before the era stamp changes;
* an unreadable component or conflicting existing Assessment aborts that row.

Rows older than v6 remain stale and regenerate through the normal cache path.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Any, Literal, cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from db import contract_materializations as cm
from db.models import ContractMaterialization, SessionLocal
from db.storage import get_storage_client
from schemas.assessment import Assessment, validate_assessment
from utils.logging import configure_logging

logger = logging.getLogger(__name__)

SOURCE_ANALYSIS_SCHEMA_VERSION = 6
TARGET_ANALYSIS_SCHEMA_VERSION = 7
Outcome = Literal["converted", "already_converted", "dry_run", "skipped"]


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _legacy_assessment(row: ContractMaterialization) -> Assessment:
    analysis = cm._hydrate(row, blob_key_attr="analysis_blob_key", inline_attr="analysis")
    tracking_plan = cm._hydrate(row, blob_key_attr="tracking_plan_blob_key", inline_attr="tracking_plan")
    predicate_trees = cm._hydrate(
        row,
        blob_key_attr="predicate_trees_blob_key",
        inline_attr="predicate_trees",
    )
    if not isinstance(analysis, dict) or not isinstance(tracking_plan, dict):
        raise ValueError("ready v6 materialization lacks analysis or tracking_plan")
    return cm._static_assessment(
        analysis,
        tracking_plan,
        predicate_trees if isinstance(predicate_trees, dict) else None,
    )


def consolidate_materialization(
    session: Session,
    row: ContractMaterialization,
    *,
    dry_run: bool = False,
) -> Outcome:
    """Convert one locked candidate, committing only after verified readback."""
    if cm.ANALYSIS_SCHEMA_VERSION != TARGET_ANALYSIS_SCHEMA_VERSION:
        raise RuntimeError(
            "materialization consolidation supports only analyzer era "
            f"{SOURCE_ANALYSIS_SCHEMA_VERSION}->{TARGET_ANALYSIS_SCHEMA_VERSION}; "
            f"runtime era is {cm.ANALYSIS_SCHEMA_VERSION}"
        )
    locked = session.execute(
        select(ContractMaterialization)
        .where(
            ContractMaterialization.chain == row.chain,
            ContractMaterialization.bytecode_keccak == row.bytecode_keccak,
        )
        .with_for_update()
    ).scalar_one()
    if locked.status != "ready" or locked.analysis_schema_version != SOURCE_ANALYSIS_SCHEMA_VERSION:
        return "skipped"

    expected = _legacy_assessment(locked)
    existing = cm.hydrate_assessment(locked) if (locked.assessment is not None or locked.assessment_blob_key) else None
    if existing is not None:
        if _canonical(existing) != _canonical(expected):
            raise ValueError("existing canonical Assessment conflicts with legacy v6 components")
        if dry_run:
            return "dry_run"
        locked.analysis_schema_version = TARGET_ANALYSIS_SCHEMA_VERSION
        session.flush()
        session.commit()
        return "already_converted"

    if dry_run:
        return "dry_run"

    client = get_storage_client()
    if client is None:
        locked.assessment = cast(dict[str, Any], expected)
        locked.assessment_blob_key = None
    else:
        key = cm._blob_key(locked.chain, locked.bytecode_keccak, "assessment")
        cm._put_blob(client, key, cast(dict[str, Any], expected))
        locked.assessment = None
        locked.assessment_blob_key = key
    session.flush()

    # Exercise the same storage path runtime readers use before making the row
    # eligible as era 7. A missing/unreadable blob raises and leaves the stamp.
    session.expire(locked, ["assessment", "assessment_blob_key"])
    readback = cm.hydrate_assessment(locked)
    if readback is None or _canonical(readback) != _canonical(expected):
        raise ValueError("canonical Assessment readback differs from legacy v6 components")
    validate_assessment(readback)
    locked.analysis_schema_version = TARGET_ANALYSIS_SCHEMA_VERSION
    session.flush()
    session.commit()
    return "converted"


def consolidate_materializations(session: Session, dry_run: bool = False) -> dict[str, int]:
    """Convert all ready v6 rows and return outcome counts.

    Each row commits independently so a corrected rerun resumes after the last
    verified row. On any error the current row is rolled back and the exception
    is raised; no later row is attempted.
    """
    keys = session.execute(
        select(ContractMaterialization.chain, ContractMaterialization.bytecode_keccak)
        .where(
            ContractMaterialization.status == "ready",
            ContractMaterialization.analysis_schema_version == SOURCE_ANALYSIS_SCHEMA_VERSION,
        )
        .order_by(ContractMaterialization.chain, ContractMaterialization.bytecode_keccak)
    ).all()
    counts = {"converted": 0, "already_converted": 0, "dry_run": 0, "skipped": 0}
    for chain, bytecode_keccak in keys:
        row = session.get(ContractMaterialization, (chain, bytecode_keccak))
        if row is None:
            counts["skipped"] += 1
            continue
        try:
            outcome = consolidate_materialization(session, row, dry_run=dry_run)
        except Exception:
            session.rollback()
            raise
        counts[outcome] += 1
        if dry_run:
            session.rollback()
    return counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    configure_logging()
    with SessionLocal() as session:
        counts = consolidate_materializations(session, dry_run=args.dry_run)
    logger.info("materialization consolidation complete", extra=counts)
    return 0


if __name__ == "__main__":
    sys.exit(main())
