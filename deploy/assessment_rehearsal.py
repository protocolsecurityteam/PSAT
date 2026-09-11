"""Rehearse the Assessment cutover against an isolated restored database copy."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy import create_engine, text


def _database_name(url: str) -> str:
    return urlsplit(url).path.lstrip("/")


def _scalar(url: str, sql: str) -> int:
    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            return int(connection.execute(text(sql)).scalar_one())
    finally:
        engine.dispose()


def _run(args: list[str], *, database_url: str | None = None, pg_url: str | None = None) -> None:
    environment = os.environ.copy()
    if database_url is not None:
        environment["DATABASE_URL"] = database_url
    if pg_url is not None:
        parsed = urlsplit(pg_url)
        environment.update(
            {
                "PGHOST": parsed.hostname or "",
                "PGPORT": str(parsed.port or 5432),
                "PGUSER": parsed.username or "",
                "PGPASSWORD": parsed.password or "",
                "PGDATABASE": parsed.path.lstrip("/"),
            }
        )
    subprocess.run(args, check=True, env=environment)


def rehearse(source_url: str, scratch_url: str, backup_file: Path) -> dict[str, object]:
    source_name = _database_name(source_url)
    scratch_name = _database_name(scratch_url)
    if not source_name or not scratch_name or source_name == scratch_name:
        raise ValueError("source and scratch must name two different databases")
    scratch_tables = _scalar(
        scratch_url,
        "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'",
    )
    if scratch_tables:
        raise RuntimeError(f"scratch database {scratch_name!r} is not empty; refusing to overwrite it")
    source_artifacts = _scalar(
        source_url,
        "SELECT count(*) FROM artifacts WHERE name IN ('assessment', 'principal_history')",
    )
    backup_file.parent.mkdir(parents=True, exist_ok=True)
    _run(["pg_dump", "--format=custom", "--no-owner", f"--file={backup_file}"], pg_url=source_url)
    backup_digest = hashlib.sha256(backup_file.read_bytes()).hexdigest()
    _run(
        ["pg_restore", "--exit-on-error", "--no-owner", f"--dbname={scratch_name}", str(backup_file)],
        pg_url=scratch_url,
    )
    _run(["uv", "run", "--no-sync", "alembic", "upgrade", "f6a1c2d3e4b5"], database_url=scratch_url)
    _run(["uv", "run", "--no-sync", "python", "-m", "services.assessment.migrate"], database_url=scratch_url)
    remaining = _scalar(
        scratch_url,
        "SELECT count(*) FROM artifacts WHERE name IN ('assessment', 'principal_history')",
    )
    manifests = _scalar(scratch_url, "SELECT count(*) FROM assessment_import_manifests")
    if remaining or manifests != source_artifacts:
        raise RuntimeError(
            f"import reconciliation failed: source={source_artifacts} manifests={manifests} remaining={remaining}"
        )
    _run(
        ["uv", "run", "--no-sync", "alembic", "-x", "assessment_cutover=stopped", "upgrade", "head"],
        database_url=scratch_url,
    )
    _run(["uv", "run", "--no-sync", "alembic", "check"], database_url=scratch_url)
    return {
        "source_database": source_name,
        "scratch_database": scratch_name,
        "source_artifacts": source_artifacts,
        "import_manifests": manifests,
        "remaining_legacy_artifacts": remaining,
        "backup_file": str(backup_file),
        "backup_sha256": backup_digest,
        "migration_head": "a8c2d4e6f901",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--scratch-url", required=True)
    parser.add_argument("--backup-file", type=Path, required=True)
    parser.add_argument("--confirm", choices=["ISOLATED SCRATCH DATABASE"], required=True)
    arguments = parser.parse_args()
    print(json.dumps(rehearse(arguments.source_url, arguments.scratch_url, arguments.backup_file), sort_keys=True))


if __name__ == "__main__":
    main()
