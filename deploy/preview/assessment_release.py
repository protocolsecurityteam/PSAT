"""Revision-aware Assessment release command for an isolated PR preview."""

from __future__ import annotations

import subprocess
import sys

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text

from db.models import DATABASE_URL

EXPANSION = "f6a1c2d3e4b5"
CONTRACTION = "a8c2d4e6f901"


def _run(*args: str) -> None:
    subprocess.run([sys.executable, "-m", *args], check=True)


def _current_revision() -> str | None:
    engine = create_engine(DATABASE_URL)
    try:
        with engine.connect() as connection:
            present = connection.execute(text("SELECT to_regclass('public.alembic_version') IS NOT NULL")).scalar_one()
            if not present:
                return None
            return connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()
    finally:
        engine.dispose()


def _contains_contraction(revision: str | None) -> bool:
    if revision is None:
        return False
    script = ScriptDirectory.from_config(Config("alembic.ini"))
    return any(item.revision == CONTRACTION for item in script.walk_revisions("base", revision))


def release() -> None:
    current = _current_revision()
    if _contains_contraction(current):
        _run("alembic", "upgrade", "head")
        return
    _run("alembic", "upgrade", EXPANSION)
    _run("services.assessment.migrate")
    _run("alembic", "-x", "assessment_cutover=stopped", "upgrade", "head")


if __name__ == "__main__":
    release()
