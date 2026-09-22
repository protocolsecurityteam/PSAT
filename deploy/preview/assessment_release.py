"""Revision-aware Assessment release command for an isolated PR preview."""

from __future__ import annotations

import subprocess
import sys

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text

from db.models import DATABASE_URL

EXPANSION = "d9e8b7c6a5f4"
CONTRACTION = "a8c2d4e6f901"


def _run(*args: str) -> None:
    subprocess.run([sys.executable, "-m", *args], check=True)


def _current_revisions() -> tuple[str, ...]:
    engine = create_engine(DATABASE_URL)
    try:
        with engine.connect() as connection:
            present = connection.execute(text("SELECT to_regclass('public.alembic_version') IS NOT NULL")).scalar_one()
            if not present:
                return ()
            return tuple(connection.execute(text("SELECT version_num FROM alembic_version")).scalars())
    finally:
        engine.dispose()


def _contains_contraction(revisions: tuple[str, ...]) -> bool:
    if not revisions:
        return False
    script = ScriptDirectory.from_config(Config("alembic.ini"))
    return any(
        item.revision == CONTRACTION for revision in revisions for item in script.walk_revisions("base", revision)
    )


def release() -> None:
    current = _current_revisions()
    if _contains_contraction(current):
        _run("alembic", "upgrade", "head")
        return
    _run("alembic", "upgrade", EXPANSION)
    _run("services.assessment.migrate")
    _run("alembic", "-x", "assessment_cutover=stopped", "upgrade", "head")


if __name__ == "__main__":
    release()
